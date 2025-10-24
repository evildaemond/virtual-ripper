import sys
import os
import asyncio
import traceback
import ntpath
from pathlib import Path
import tqdm
import inspect
import math

from typing import List, Dict
from adiskreader.external.aiocmd.aiocmd import aiocmd
from adiskreader.external.aiocmd.aiocmd.list_completer import ListPathCompleter
from adiskreader import logger
from adiskreader._version import __banner__

from adiskreader.datasource import DataSource
from adiskreader.disks import Disk

# Addons
import json
import argparse
import hashlib
from impacket.winregistry import Registry
from rich import print
from rich.table import Table
from rich.console import Console


class DiskBrowser(aiocmd.PromptToolkitCmd):
	def __init__(self):
		aiocmd.PromptToolkitCmd.__init__(self, ignore_sigint=False) #Setting this to false, since True doesnt work on windows...
		self.__datasource = None
		self.__disk = None
		self.__partitions = []
		self.__partition = None
		self.__partition_id = None
		self.__filesystem = None
		self.__current_directory = None
		self.__buffer_dir_contents = False #True
		self.__subdirs = {}
		self.__files = {}
	
	def _getdir_completions(self):
		return ListPathCompleter(get_current_dirs = self.get_current_dirs)
	
	def _sid_completions(self):
		return ListPathCompleter(get_current_dirs = self.get_current_files)
	
	def _dirsid_completions(self):
		return ListPathCompleter(get_current_dirs = self.get_current_dirs)
	
	def get_current_dirs(self):
		return list(self.__subdirs.keys())

	def get_current_files(self):
		return list(self.__files.keys())

	def handle_exception(self, e, msg = None):
		#providing a more consistent exception handling
		frame = inspect.stack()[1]
		caller = frame.function
		args, _, _, values = inspect.getargvalues(frame[0])
		caller_args = {arg: values[arg] for arg in args}
		if 'self' in caller_args:
			del caller_args['self']
		if len(caller_args) > 0:
			caller += ' '
			for k,v in caller_args.items():
				caller += '%s=%s ' % (k,v)
			caller = caller[:-1]
		if caller.startswith('do_'):
			caller = caller[3:]
		to_print = 'CMD: "%s" ERR: ' % caller
		to_print += 'Error: %s' % e
		if msg is not None:
			to_print = msg+' '+to_print
		print(to_print)
		
		formatted_exception = "".join(traceback.format_exception(type(e), e, e.__traceback__))
		logger.debug("Traceback:\n%s", formatted_exception)
		return False, e	

	async def _on_close(self):
		pass

	async def do_close(self):
		try:
			if self.__datasource is not None:
				await self.__datasource.close()
			return True, None
		except Exception as e:
			return self.handle_exception(e)

	async def do_partinfo(self, to_print=True):
		try:
			self.__partitions = await self.__disk.list_partitions()
			if to_print is True:
				print('Partitions on current disk:')
				for i, part in enumerate(self.__partitions):
					print(f'[{i}] {part}')
			return True, None
		except Exception as e:
			return self.handle_exception(e)	

	async def do_open(self, filepath:str):
		try:
			self.__datasource = await DataSource.from_url(filepath)
			self.__disk = await Disk.from_datasource(self.__datasource)
			await self.do_partinfo(False)
			if len(self.__partitions) == 0:
				print('No partitions found!')
				return False, None
			if len(self.__partitions) == 1:
				await self.do_mount(0)
				return True, None
			return True, None
		except Exception as e:
			traceback.print_exc()
			return self.handle_exception(e)

	async def do_mount(self, partition_id:int):
		try:
			partition_id = int(partition_id)
			self.__partition = self.__partitions[partition_id]
			self.__filesystem = await self.__partition.mount()
			self.__current_directory = await self.__filesystem.get_root()
			if self.__buffer_dir_contents is True:
				await self.do_refreshcurdir()
			dirpath = await self.__current_directory.resolve_full_path()
			self.__partition_id = partition_id
			self.prompt = '[%s][%s] $ ' % (self.__partition_id, dirpath)
			return True, None
		except Exception as e:
			return self.handle_exception(e)

	async def do_dir(self):
		return await self.do_ls()
	
	async def do_ls(self):
		try:
			if self.__filesystem is None:
				print('No mounted (active) filesystem!')
				return None, Exception('No mounted (active) filesystem!')
			if self.__current_directory is None:
				print('No directory selected!')
				return None, Exception('No directory selected!')
			
			async for entry in self.__current_directory.get_console_output():
				print(entry)
			
			return True, None
		except Exception as e:
			return self.handle_exception(e)
	
	async def do_get(self, file_name:str, outfile_path:str = None):
		try:
			if self.__filesystem is None:
				print('No mounted (active) filesystem!')
				return None, Exception('No mounted (active) filesystem!')
			if self.__current_directory is None:
				print('No directory selected!')
				return None, Exception('No directory selected!')
			
			file_obj = await self.__current_directory.get_child(file_name)
			if file_obj is None:
				print('File not found!')
				return False, None
			
			filename = await file_obj.resolve_full_path()
			file_obj = await self.__filesystem.open(filename)
			await file_obj.seek(0,2)
			file_size = await file_obj.tell()
			await file_obj.seek(0,0)
			pbar = tqdm.tqdm(total=file_size, unit='B', unit_scale=True)
			if outfile_path is not None:
				if os.path.isdir(outfile_path) is True:
					file_name = ntpath.basename(filename)
					file_name = os.path.join(outfile_path, file_name)
				else:
					file_name = outfile_path
			with open(file_name, 'wb') as f:
				while True:
					data = await file_obj.read(1024*1024)
					if data == b'':
						break
					f.write(data)
					pbar.update(len(data))
			return True, None
		except Exception as e:
			return self.handle_exception(e)

	async def do_getdir(self, dir_name:str):
		try:
			if self.__filesystem is None:
				print('No mounted (active) filesystem!')
				return None, Exception('No mounted (active) filesystem!')
			if self.__current_directory is None:
				print('No directory selected!')
				return None, Exception('No directory selected!')
			
			if dir_name not in self.__subdirs and (dir_name.find('/')!= -1 or dir_name.find('\\')!= -1):
				dir_obj = await self.__filesystem.get_record_by_path(dir_name)
			else:
				dir_obj = await self.__current_directory.get_child(dir_name)
			if dir_obj is None:
				print('Directory not found!')
				return False, None
			if dir_obj.is_directory() is False:
				print('Not a directory!')
				return False, None
			
			base_path = Path.cwd()
			rem_dir_path = await dir_obj.resolve_full_path()
			async for root, dirs, files in self.__filesystem.walk(rem_dir_path):
				indep_root = root.replace('\\', '/')
				if indep_root.startswith('/'):
					indep_root = indep_root[1:]
				root_path = base_path / Path(indep_root)
				root_path.mkdir(parents=True, exist_ok=True)
				for dir in dirs:
					dirpath = root_path / dir
					if dirpath.resolve().is_relative_to(base_path) is False:
						print('Skipping %s (unsafe)' % dirpath)
						continue
					dirpath.mkdir(parents=True, exist_ok=True)
				for f in files:
					loc_filepath = root_path / f
					if loc_filepath.resolve().is_relative_to(base_path) is False:
						print('Skipping %s (unsafe)' % loc_filepath)
						continue
					rem_filepath = '\\'.join([root, f])
					file_obj = await self.__filesystem.open(rem_filepath)
					await file_obj.seek(0,2)
					file_size = await file_obj.tell()
					await file_obj.seek(0,0)
					pbar = tqdm.tqdm(total=file_size, unit='B', unit_scale=True)
					with open(loc_filepath, 'wb') as f:
						while True:
							data = await file_obj.read(1024*1024)
							if data == b'':
								break
							f.write(data)
							pbar.update(len(data))
			return True, None
		except Exception as e:
			traceback.print_exc()
			return self.handle_exception(e)

	async def do_refreshcurdir(self):
		try:
			self.__subdirs = {}
			self.__files = {}
			async for etype, name, entry in self.__current_directory.get_children():
				if etype == 'dir':
					self.__subdirs[name] = entry
				elif etype == 'file':
					self.__files[name] = entry
				# otherwise we skip
			return True, None
		except Exception as e:
			return self.handle_exception(e)	

	async def do_cd(self, directory_name):
		try:
			# a partition must be mounted
			if self.__partition is None:
				print('No partition mounted!')
				return False, None
			
			# we want the previous directory
			if directory_name == '..':
				self.__current_directory = await self.__current_directory.get_parent()
				dirpath = await self.__current_directory.resolve_full_path()
				self.prompt = '[%s][%s] $ ' % (self.__partition_id, dirpath)
				if self.__buffer_dir_contents is True:
					_, err = await self.do_refreshcurdir()
					if err is not None:
						raise err
				return True, None
			
			# we want to go to a specific directory
			if directory_name.find('\\') != -1:
				if self.__current_directory is None:
					print('No directory selected for relative path traversal!')
					return False, None
				curpath = await self.__current_directory.resolve_full_path()
				directory_name = '\\'.join([curpath, directory_name])
					
				# this better be a full path
				newdir = await self.__filesystem.get_record_by_path(directory_name)
				if newdir is None:
					print('Directory not found!')
					return False, None
				self.__current_directory = newdir
				dirpath = await self.__current_directory.resolve_full_path()
				self.prompt = '[%s][%s] $ ' % (self.__partition_id, dirpath)
				if self.__buffer_dir_contents is True:
					_, err = await self.do_refreshcurdir()
					if err is not None:
						raise err
				return True, None
			
			# this is a relative path
			newdir = await self.__current_directory.get_child(directory_name)
			if newdir is None:
				raise Exception('Directory not found!')
			self.__current_directory = newdir
			dirpath = await self.__current_directory.resolve_full_path()
			self.prompt = '[%s][%s] $ ' % (self.__partition_id, dirpath)
			if self.__buffer_dir_contents is True:
				_, err = await self.do_refreshcurdir()
				if err is not None:
					raise err
			return True, None
			
			
		except Exception as e:
			traceback.print_exc()
			return self.handle_exception(e)

	## Added
	HKLM_SAM_Registry = None
	HKLM_SYSTEM_Registry = None
	HKLM_SECURITY_Registry = None
	HKLM_SOFTWARE_Registry = None
	json_rules = []

	negative_fullpath_rules = []
	negative_partialpath_rules = []

	# General Utils
	async def hash_file(self, file_path):
		"""
		Create an SHA256 hash of a file
		"""
		filehash = hashlib.sha256()
		with open(file_path, "rb") as f:
			for chunk in iter(lambda: f.read(4096), b""):
				filehash.update(chunk)
		return filehash.hexdigest()

	async def virtual_disk_fingerprint(self, file_path):
		"""
		Collect key information on the disk to allow us to fingerprint it for later use
		"""
		if (file_path.split(':')[0].lower()) in ['file']:
			file_path = (file_path.split('//')[-1]).lower()

		if self.__disk is None:
			print("No disk image loaded!")
			return
		if self.__partitions is None or len(self.__partitions) == 0:
			print("No partitions found!")
			return

		# Create a SHA256 hash of the disk image
		#disk_hash = await self.hash_file(file_path)
		#print(f"Disk SHA256: {disk_hash}")

		# Get the total size of the disk image
		disk_size = os.path.getsize(file_path)
		disk_size_pretty = pretty_print_size(disk_size)
		print(f"Disk Size: {disk_size_pretty} ({disk_size} bytes)")

		# Get the number of partitions
		num_partitions = len(self.__partitions)
		print(f"Number of Partitions: {num_partitions}")

		# Do a dir listing over the root of each partition
		self.__partitions = await self.__disk.list_partitions()

		dir_listings = []
		partition_array = []
		for i, part in enumerate(self.__partitions):
			part = str(part)
			size_split = (part.split(":", 1))[1]
			description = (size_split.split(")", 1))[1]
			size_split = (size_split.split("(", 1))[0]
			totalsize = (int((size_split.split("-", 1)[0]).strip()) + int((size_split.split("-", 1)[1]).strip()))
			totalsize = int(totalsize * 512)  # Convert from sectors to bytes (assuming 512 byte sectors)
			totalsize_pretty = pretty_print_size(totalsize)
			data = [i, totalsize, totalsize_pretty, description]
			partition_array.append(data)
			print(f"Partition {i}: {totalsize} - {description}")

			valid, _ = await self.do_mount(i)
			if valid == True:
				await self.do_refreshcurdir()
				current_directory = await self.__filesystem.get_root()
				curpath = await current_directory.resolve_full_path()
				entries = []
				async for etype, name, entry in current_directory.get_children():
					if etype == 'dir':
						entries.append((etype, name, None, str(entry.time_created), str(entry.time_modified)))
					elif etype == 'file':
						entries.append((etype, name, str(pretty_print_size(entry.real_size)), str(entry.time_created), str(entry.time_modified)))

				dir_listings.append((i, entries))


		console = Console()
		table = Table(title="Disk Fingerprint")
		table.add_column("Attribute", style="cyan", no_wrap=True)
		table.add_column("Value", style="white", no_wrap=False)
		table.add_row("Disk Image", file_path)
		table.add_row("Target Name", str(self.__target_name))
		table.add_row("Disk Size", f"{disk_size_pretty} ({disk_size} bytes)")
		table.add_row("Number of Partitions", str(num_partitions))
		for part in partition_array:
			table.add_row(f"Partition {part[0]} Size", f"{part[2]} ({part[1]} bytes) - {part[3]}")
		console.print(table)

		for listing in dir_listings:
			part_num = listing[0]
			entries = listing[1]
			table = Table(title=f"Partition {part_num} Root Directory Listing")
			table.add_column("Type", style="cyan", no_wrap=True)
			table.add_column("Name", style="white", no_wrap=False)
			table.add_column("Size", no_wrap=True)
			table.add_column("Created", no_wrap=True)
			table.add_column("Modified", no_wrap=True)
			for entry in entries:
				etype = entry[0]
				name = entry[1]
				real_size = entry[2]
				time_created = entry[3]
				time_modified = entry[4]
				table.add_row(etype, name, real_size, time_created, time_modified)
			console.print(table)

	# File System Utils
	async def walk_children(self, current:str, target:str, output:bool = False, outdir:Path = None, filename:str = None, recursive:bool = True, maxdepth:int = 5):
		directory_name = '\\'.join([current, target])
		depth = len(directory_name.split('\\'))
		#print(f"Current depth: {depth} / Max depth: {maxdepth}")
		if depth >= maxdepth:
			return
		newdir = await self.__filesystem.get_record_by_path(directory_name)
		#print(f"Entering directory: {directory_name}")
		_, err = await self.do_refreshcurdir()
		if err is None and newdir is not None:
			async for etype, name, entry in newdir.get_children():
				if (output is True):
					print(directory_name + '\\' + name)
				if outdir is not None:
					outdir.mkdir(parents=True, exist_ok=True)
				if filename is not None:
					#print(f"Writing to {outdir / filename}")
					with open(outdir / filename, 'a', encoding='utf-8') as f:
						# Weird issue where some dirnames have a . at the start for filenames, so just going to filter it here
						directory_name = directory_name.lstrip('.\\')
						#if directory_name[0] == "\\":
						#	directory_name = directory_name[1:]
						f.write('\\' + directory_name + '\\' + name + '\n')
				if etype == 'dir':
					filtername = (directory_name + "\\" + name.lower())
					#print(f"Checking directory: {filtername}")
					for p in self.negative_partialpath_rules:
						#print(f"Checking against negative partialpath rule: {p}")
						if p in filtername:
							#print(f"Skipping {filtername} due to negative partialpath rule")
							break
					else:
						curpath = await newdir.resolve_full_path()
						if recursive is True:
							await self.walk_children(curpath, name, output, outdir, filename, recursive, maxdepth=maxdepth)
				elif etype == 'file':
					pass

	async def walk_dir(self, output:bool = False, outdir:Path = None, filename:str = None, recursive:bool = True, maxdepth:int = 5):
		ignore_list = ['system volume information', '$recycle.bin', '$sysreset', '.', '..']

		current_directory = await self.__filesystem.get_root()
		curpath = await current_directory.resolve_full_path()
		async for etype, name, entry in current_directory.get_children():
			if (output is True):
				print('\\' + name)
			if outdir is not None:
				outdir.mkdir(parents=True, exist_ok=True)
			if filename is not None:
				with open(outdir / filename, 'a', encoding='utf-8') as f:
					f.write('\\' + name + '\n')
			if etype == 'dir':
				filtername = (name.lower().split('\\')[-1]).split('/')[ -1]
				#print(f"Checking directory: {filtername}")
				if filtername in ignore_list:
					continue
				else:
					curpath = await current_directory.resolve_full_path()
					if recursive is True:
						#print(f"Max Depth: {maxdepth}")
						await self.walk_children(curpath, name, output, outdir, filename, recursive, maxdepth=maxdepth)
			elif etype == 'file':
				pass

	async def get_dir_ls(self, dir_path:str):
		self.__current_directory = await self.__filesystem.get_root()
		if self.__current_directory != dir_path:
			await self.do_cd(dir_path)
		await self.do_refreshcurdir()
		return self.__subdirs

	async def extract_file_to_dir(self, file_path:str, file:str, outdir:str, folder:str = None):
		# Pre-flight check, the filepath exists
		outdir.mkdir(parents=True, exist_ok=True)
		if folder is not None:
			outdir = outdir / folder
			outdir.mkdir(parents=True, exist_ok=True)

		print(f"Extracting {file_path}\\{file} to {outdir}")

		self.__current_directory = await self.__filesystem.get_root()
		if self.__current_directory != file_path:
			await self.do_cd(file_path)
		await self.do_refreshcurdir()
		valid, _ = await self.do_get(file, outdir)
		if valid is False:
			return False
		return True

	# Rules Processor
	async def load_rules(self):
		# Load rules from the rules directory
		rules = []
		for rule in os.listdir('rules'):
			if rule.endswith('.json'):
				rules.append(os.path.join('rules', rule))
		json_rules = []
		for rule in rules:
			try:
				with open(rule, 'r', encoding='utf-8') as f:
					data = json.load(f)
					json_rules.append(data)
			except Exception as e:
				print(f"Error loading rule {rule}: {e}")
		self.json_rules	 = json_rules

	async def pre_process_rules(self):
		"""
		Pre-Process netgative ruleset for ignoring files/directories during processing
		"""
		for rule in self.json_rules:
			ruledata = rule.get('rule', {})
			if ruledata.get('action', None) == 'ignore':
				ruledata = rule.get('rule', {})
				match = ruledata.get('match', [])
				operation = rule.get('operation', 'None')
				matchtype = ruledata.get('matchtype', 'None')

				if operation == 'filesystem':
					if matchtype == 'fullpath':
						for m in match:
							m = m.replace('/', '\\')
							#print(f"Adding negative fullpath rule: {m.lower()}")
							self.negative_fullpath_rules.append(m.lower())
					elif matchtype == 'partialpath':
						for m in match:
							m = m.replace('/', '\\')
							#print(f"Adding negative partialpath rule: {m.lower()}")
							self.negative_partialpath_rules.append(m.lower())

	async def process_rules(self):
		"""
		Process all rules against the current partition based upon the the operation and match
		"""
		await self.pre_process_rules()

		for rule in self.json_rules:
			rulename = rule.get('rulename', 'None')
			selector = rule.get('selector', 'None')
			operation = rule.get('operation', 'None')
			ruledata = rule.get('rule', {})

			matchtype = ruledata.get('matchtype', 'None')
			action = ruledata.get('action', None)
			if action == "extract" or action == "load" or action == "walk":
				extractLocation = ruledata.get('extractLocation', None)
			if action == "walk":
				maxdepth = ruledata.get('maxdepth', 5)
			match = ruledata.get('match', [])

			console = Console()
			console.rule(f"Rule: {rulename}")
			console.print(f"Processing Rule: {rulename}")

			if action == "extract":
				await self.process_rule_extract(operation=operation, matchtype=matchtype, match=match, extractLocation=extractLocation)
			elif action == "load":
				await self.process_rule_load(operation=operation, matchtype=matchtype, match=match, extractLocation=extractLocation)
			elif action == "walk":
				await self.process_rule_walk(operation=operation, matchtype=matchtype, match=match, extractLocation=extractLocation, maxdepth=maxdepth)
			elif action == "registry_get_value":
				await self.process_query_registry(operation=operation, matchtype=matchtype, match=match, get_value=True)
			elif action == "registry_get_keys":
				await self.process_query_registry(operation=operation, matchtype=matchtype, match=match, get_value=False)
			elif action == "ignore":
				# Ignore rules are pre-processed
				continue
			else:
				console.print(f"Action {action} not implemented yet")

			#console.print(f"Completed Rule: {rulename}")

	# Rule Actions
	## Filesystem
	async def process_rule_extract(self, operation:str, matchtype:str, match:List[str], extractLocation:str = None):
		if operation == 'filesystem':
			if matchtype == 'fullpath':
				for m in match:
					#print(f"Extracting file: {m}")
					filepath = m.replace('/', '\\')
					dirpath = '\\'.join(filepath.split('\\')[:-1])
					filename = filepath.split('\\')[-1]
					outdir = Path.cwd() / 'loot' / self.__target_name
					await self.extract_file_to_dir(dirpath, filename, outdir, extractLocation)
			elif matchtype == 'partialpath':
				# Not implemented yet
				pass
			elif matchtype == 'wildcard':
				# Not implemented yet
				pass
		elif operation == 'registry':
			# Not implemented yet
			pass

	async def process_rule_load(self, operation:str, matchtype:str, match:List[str], extractLocation:str = None):
		if operation == 'filesystem':
			if matchtype == 'fullpath':
				for m in match:
					#print(f"Extracting file: {m}")
					filepath = m.replace('/', '\\')
					dirpath = '\\'.join(filepath.split('\\')[:-1])
					filename = filepath.split('\\')[-1]
					outdir = Path.cwd() / 'loot' / self.__target_name
					valid = await self.extract_file_to_dir(dirpath, filename, outdir, extractLocation)
					#print(f"Valid: {valid}")
					if valid != False:
						name = filename.split('.')[-1].upper() + '_Registry'
						#print(f"Loading {name} from {outdir / extractLocation / filename}")
						if name == 'SAM_Registry':
							self.HKLM_SAM_Registry = Registry(outdir / extractLocation / filename)
						elif name == 'SYSTEM_Registry':
							self.HKLM_SYSTEM_Registry = Registry(outdir / extractLocation / filename)
						elif name == 'SECURITY_Registry':
							self.HKLM_SECURITY_Registry = Registry(outdir / extractLocation / filename)
						elif name == 'SOFTWARE_Registry':
							self.HKLM_SOFTWARE_Registry = Registry(outdir / extractLocation / filename)

	async def process_rule_walk(self, operation:str, matchtype:str, match:List[str], extractLocation:str = None, maxdepth:int = 5):
		if operation == 'filesystem':
			if matchtype == 'fullpath':
				for m in match:
					# Wildcard check
					dirpaths = []
					if '*' in m:
						# Wildcard is used as a ANY replacement for a directory, when it is used, we use the root directory first then
						# walk down to the target directory
						m_split = m.split('*')
						#print(f"Walking wildcard: {m_split}")
						root_dir = m_split[0].replace('/', '\\')
						#for i in m_split:
							#print(f"Split part: {i}")
						target_dir = m_split[1].replace('/', '\\') if len(m_split) > 1 else ''
						if root_dir.endswith('\\'):
							root_dir = root_dir[:-1]
						dirs = await self.get_dir_ls(root_dir)
						if dirs is not None:
							for name in dirs:
								wildcard_path = root_dir + '\\' + name + target_dir
								#print(f"Walking path: {wildcard_path}")
								dirpaths.append(wildcard_path)
					else:
						dirpaths.append(m.replace('/', '\\'))

					for m in dirpaths:
						filepath = m.replace('/', '\\')
						dirpath = '\\'.join(filepath.split('\\')[:-1])
						if extractLocation is not None:
							outdir = Path.cwd() / 'loot' / self.__target_name / extractLocation
						else:
							outdir = Path.cwd() / 'loot' / self.__target_name
						self.__current_directory = await self.__filesystem.get_root()
						curpath = await self.__current_directory.resolve_full_path()

						if dirpath == "":
							outfile = "root" + "_" + "dirwalk" + '.txt'
							#print(f"Max Depth: {maxdepth}")
							await self.walk_dir(output=False, outdir=outdir, filename=outfile, recursive=True, maxdepth=maxdepth)
						else:
							outfile = dirpath.replace('\\', '-') + "_" + "dirwalk" + '.txt'
							await self.walk_children(current=curpath, target=dirpath, output=False, outdir=outdir, filename=outfile, recursive=True, maxdepth=maxdepth)

	## Registry
	async def process_query_registry(self, operation:str, matchtype:str, match:str, get_value:bool = False):
		if operation != 'registry':
			print("Operation must be 'registry' for registry queries")
			return
		else:
			if matchtype == 'fullpath':
				for m in match:
					# Split the registry type based on the path to verify what registry it is being read from (If using that format)
					regtype = None
					if m.split(":")[1] != "":
						regtype = m.split(":")[0].lower()
						m = (m.split(":", 1)[1])[1:]
					if regtype is not None:
						registryName = (m.split('\\', 1)[0]).upper()
						path = m.split('\\', 1)[1] if len(m.split('\\', 1)) > 1 else ''
						#print(f"Querying {regtype.upper()} registry for {registryName} - {path}")
						if registryName == "SYSTEM":
							if self.HKLM_SYSTEM_Registry is None:
								print("No SYSTEM registry loaded!")
								continue
							regquery = self.HKLM_SYSTEM_Registry
						elif registryName == "SOFTWARE":
							if self.HKLM_SOFTWARE_Registry is None:
								print("No SOFTWARE registry loaded!")
								continue
							regquery = self.HKLM_SOFTWARE_Registry
						else:
							return

						# Capture and Replace Query Objects
						queryObjects = ['{currentControlSet}']
						for i in queryObjects:
							if i in path:
								if i == '{currentControlSet}':
									currentControlSet = regquery.getValue('\\Select\\Current')[1]
									currentControlSet = "ControlSet%03d" % currentControlSet
									path = path.replace(i, currentControlSet)

						# If we are getting just a single value from a registry location
						if get_value is True:
							if "*" in path:
								rootPath = (path.split('*')[0]).strip('\\')
								restofPath = ('*'.join(path.split('*')[1:])).lstrip('\\')
								queryInfo = regquery.findKey(rootPath)
								#print(f"Registry Path: {rootPath}")
								if queryInfo is not None:
									#print(f"queryInfo: {queryInfo}")
									out = regquery.enumKey(queryInfo)
									for i in out:
										#print(f"Wildcard Key: {i}")
										if restofPath != "":
											path = "%s\\%s\\%s" % (rootPath, i, restofPath)
										else:
											path = "%s\\%s" % (rootPath, i)
										value = path.replace('*', i).split('\\')[-1]
										path = '\\'.join(path.replace('*', i).split('\\')[:-1])
										val = regquery.getValue(path, value)
										if val is None:
											#print(f"Value {value} not found in {path}")
											continue
										else:
											val = val[1]
											if isinstance(val, bytes):
												try:
													val = val.decode('utf-16-le')
												except:
													val = val.hex()
											elif val is None:
												val = '<None>'
											console = Console()
											table = Table(title=f"{path}\\{value}")
											table.add_column("Name", style="cyan", no_wrap=True)
											table.add_column("Value", style="white", no_wrap=True)
											table.add_row(value, val)
											console.print(table)
							value = path.split('\\')[-1]
							path = '\\'.join(path.split('\\')[:-1])
							val = regquery.getValue(path, value)
							if val is None:
								#print(f"Value {value} not found in {path}")
								continue
							else:
								val = val[1]
								if isinstance(val, bytes):
									try:
										val = val.decode('utf-16-le')
									except:
										val = val.hex()
								elif val is None:
									val = '<None>'
								console = Console()
								table = Table(title=path)
								table.add_column("Name", style="cyan", no_wrap=True)
								table.add_column("Value", style="white", no_wrap=True)
								table.add_row(value, val)
								console.print(table)

						# Otherwise we are retrieving all values from a registry location
						else:
							if "*" in path:
								rootPath = (path.split('*')[0]).strip('\\')
								queryInfo = regquery.findKey(rootPath)
								#print(f"Registry Path: {rootPath}")
								if queryInfo is not None:
									#print(f"queryInfo: {queryInfo}")
									out = regquery.enumKey(queryInfo)
									for i in out:
										#print(f"Wildcard Key: {i}")
										enumOut = []
										a = (regquery.findKey("%s\\%s" % (rootPath, i)))
										a = (regquery.enumValues(a))
										for x in a:
											x = x.decode() if isinstance(x, bytes) else x
											value = regquery.getValue("%s\\%s\\%s" % (rootPath, i, x))
											if value is None:
												continue
											else:
												value = value[1]
											if isinstance(value, bytes):
												try:
													value = value.decode('utf-16-le')
												except:
													value = value.hex()
											if value is None:
												value = '<None>'
											enumOut.append((x, value))
										if len(enumOut) > 0:
											console = Console()
											title = f"{rootPath}\\{i}"
											table = Table(title=title)
											table.add_column("Name", style="cyan", no_wrap=True)
											table.add_column("Value", style="white", no_wrap=True)
											for item in enumOut:
												table.add_row(str(item[0]), str(item[1]))
											console.print(table)

							else:
								enumOut = []
								queryInfo = regquery.findKey(path)
								#print(f"Registry Path: {path}")
								if queryInfo is not None:
									#print(f"queryInfo: {queryInfo}")
									out = regquery.enumKey(queryInfo)
									for i in out:
										a = (regquery.findKey("%s\\%s" % (path, i)))
										a = (regquery.enumValues(a))
										for x in a:
											x = x.decode() if isinstance(x, bytes) else x
											value = regquery.getValue("%s\\%s\\%s" % (path, i, x))
											if value is None:
												continue
											else:
												value = value[1]
											if isinstance(value, bytes):
												try:
													value = value.decode('utf-16-le')
												except:
													value = value.hex()
											if value is None:
												value = '<None>'
											enumOut.append((x, value))
											#print(f"{m}\\{i}\\{x}: {value}")
									if len(enumOut) > 0:
										console = Console()
										table = Table(title=path)
										table.add_column("Name", style="cyan", no_wrap=True)
										table.add_column("Value", style="white", no_wrap=True)
										for item in enumOut:
											table.add_row(str(item[0]), str(item[1]))
										console.print(table)

	# Primary Mount and Enumeration
	async def do_automount_and_enum(self, file_path):
		await self.do_open(file_path)
		self.__partitions = await self.__disk.list_partitions()

		self.__target_name = (file_path.replace('\\', '/')).split("/")[-1].split('.')[0]
		outdir = Path.cwd() / 'loot'  / self.__target_name

		await self.virtual_disk_fingerprint(file_path)


		partition_array = []
		for i, part in enumerate(self.__partitions):
			part = str(part)
			size_split = (part.split(":", 1))[1]
			description = (size_split.split(")", 1))[1]
			size_split = (size_split.split("(", 1))[0]
			totalsize = (int((size_split.split("-", 1)[0]).strip()) + int((size_split.split("-", 1)[1]).strip()))
			totalsize = int(totalsize * 512)  # Convert from sectors to bytes (assuming 512 byte sectors)
			data = [i, totalsize, description]
			partition_array.append(data)

		## Loop through all partitions and mount each one
		for part in partition_array:
			print(f"Mounting partition {part[0]}: {part[2]}")
			valid, _ = await self.do_mount(part[0])
			#print(valid)
			if valid == True:
				#await self.do_ls()
				await self.load_rules()
				await self.process_rules()

		return True, None

def pretty_print_size(size_bytes):
    """
    Converts a size in bytes to a human-readable format.

    Args:
        size_bytes (int): The size in bytes.

    Returns:
        str: The size in a human-readable format (e.g., '10.5 MB').
    """
    if size_bytes == 0:
        return "0B"
    
    size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    
    return f"{s} {size_name[i]}"

async def amain(file_path:str, commands:List[str] = [], continue_on_error:bool = False, no_interactive:bool=False):
	client = DiskBrowser()
	_, err = await client._run_single_command('automount_and_enum', [file_path])
	await client.do_close()

def _build_cli():
	p = argparse.ArgumentParser(
        prog="Virtual Ripper", 
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="A rules based virtual disk analysis tool",
    )
	p.add_argument("--file", "-f", help="The target file to analyze", required=True)
	return p

def main():
	args = _build_cli().parse_args()

	if args.file is None:
		print('No file specified!')
		sys.exit(1)

	fileLocation = 'file://' + args.file

	asyncio.run(
		amain(
			fileLocation,
		)
	)

if __name__ == '__main__':
	main()
