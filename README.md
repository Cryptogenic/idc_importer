# IDC Importer (Plugin)
Author: **SpecterDev**

_Allows users to import idc database dumps from IDA into Binary Ninja._

## Description

Making the switch from IDA to Binary Ninja but need your function names and symbols to carry over? This plugin will take an IDC file and automatically import the functions, strings, and comments.

## Installation

To install this plugin, go to Binary Ninja's plugin directory (can be found by going to Tools -> "Open Plugin Folder"), and run the following command:

```
git clone https://github.com/Cryptogenic/idc_importer
```

Note you'll probably need to restart Binary Ninja for the plugin to load. You should now see the "Import IDC File" option under the Tools menu.

## Usage

After installation, an option labelled "Import IDC File" under the Tools menu should appear. Clicking that will reveal the following options dialogue:

![](https://i.imgur.com/NV8LF2H.png)



Simply browse and open the IDC file you wish to import and click OK - the plugin will handle the rest.

### Known Issues / Stipulations

- Comments made in IDA outside of functions will not carry over. This is because Binary Ninja (at least currently) does not allow setting comments in non-function areas.
- Attempting to load an IDC of a different binary can seriously mess with your BNDB, as the plugin also tries to port function definitions, not just names!
- Support for porting structures / additional types is planned for in the near future.

## Minimum Version

This plugin requires the following minimum version of Binary Ninja:

 * release - 1.0.13
 * dev - 1.0.dev-175


## License

This plugin is released under a [MIT](LICENSE) license.