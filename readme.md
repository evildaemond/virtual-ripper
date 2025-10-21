# Virtual Ripper

Virtual Ripper is a rules based virtual disk scanner, that uses the base of [adiskreader](https://github.com/skelsec/adiskreader) to run a set of rules against a virtual disk file and read or extract contents.

## Features

- Parsing of virtual disk files including RAW, VHD, and VHDX
- Preset rules for basic extraction of registry information and directory walking
- Automatic folder creation and file extraction

## Requirements

The script is written in Python and is meant to be an add-on for the original, there are some additonal python requirements.

```text
rich
impacket
argparse
json
```

## Installation

```bash
git clone https://github.com/skelsec/adiskreader
cd adiskreader
pip install .
cd ../
git clone https://github.com/evildaemond/virtual-ripper
cd virtual-ripper
pip install -r requirements.txt
```

## Usage

```bash
python virtual-ripper.py -f file.vhdx
```

## Rules

Rules schema is built in JSON, information can be found inside of the python script.

### Rule Name

A generic rule name for the rule that is being run against the collection, by default this rule name does not have to be anything special, just something for tagging and debug purposes. 

### Operation

Operation is where the query will happen for this rule, there are multiple sources of operations where this can occur, and we can treat it like a selector between each one.

- `filesystem` - For enumeration of the filesystem or directory
- `registry` - For queries to the registry within Windows based systems

### Rule

The rule is the match and action used for the rule, and is written to be expansible. 

#### MatchType

The type of match used, this can come in different flavors depending, and allows for the ability to include multiple path locations or registry path locations. 

- `fullpath` - The full filepath of the directory or registry location
- `partialpath` - The partial path of the directory or registry location (Currently not implemented)

On top of these, we can add match filters for certain areas or words, where the filter comes from another location, for example

- `currentControlSet` - The currentControlSet for Reg in System
- `wildcard` - The wildcard path for a certain directory location, so for example `\\users\\*`

#### Action

The action to take for the task based on the rule triggering

- `extract` - Extract the file or registry values from the system and place it within the loot folder
- `load` - Load the data into another processor (Currently only implemented for `registry`)
- `treedir` - Create a tree of the directory or location, and put the tree in the loot folder
- `registry_get_keys` - Get all keys and values from a registry path
- `registry_get_value` -  Get a specific value from a registry path


#### Extract Location

This is the folder location for the data to be extracted to for a specific rule, it will automatically make the folder under the `/loot/` directory for the filename of the virtual disk file, so for example if we put `treedir` we would have the files put in the `/loot/$filename/treedir/` directory.

#### Match

The actual collection of items to match

```json
"match": [
	"Windows\\System32\\config\\SAM",
	"Windows\\System32\\config\\SYSTEM",
	"Windows\\System32\\config\\SECURITY",
	"Windows\\System32\\config\\SOFTWARE"
]
```

