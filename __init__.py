"""
IDC Importer
-
Imports an IDC database dump from IDA and imports the function names, strings, and comments into binja.
"""

from binaryninja import *

# Extracts a substring between two deliminators in a string
def getBetween(s, first, last):
    try:
        start = s.index(first) + len(first)
        end = s.index(last, start)
        return s[start:end]
    except ValueError:
        return ''
    return ''

# Used for functions and strings
class SymbolDef(object):
	def __init__(self, start, end):
		self.name 	= ''
		self.start 	= start
		self.end 	= end

	def setName(self, name):
		self.name = name

# Used for line comments (; in IDA, // in binja)
class CommentDef(object):
	def __init__(self, start, comment):
		self.comment = comment
		self.start   = start

# Sets up the status text in binja and calls the import function, providing a binary view
class ImportIDCInBG(BackgroundTaskThread):
	def __init__(self, binaryView, idcFile):
		global task

		BackgroundTaskThread.__init__(self, "Importing ID...", False)

		# A binaryview is needed for common binja functions
		self.binaryView = binaryView
		self.file = idcFile

	def run(self):
		(success, err) = importIDC(self.file, self.binaryView)

		if success:
			log_info("IDC import completed successfully.")
		else:
			log_error(err)

def importIDC(file, binaryView):
	# We'll compile a dictionary of all functions, comment, and string definitions found.
	# The key will be the start address, and the value the object definition.
	functionList  = {}
	commentList   = {}
	stringDefList = {}

	notifyUserNonFunctionComments = False

	# We'll get all the info we need all in two sweeps. The first pass will get the definitions,
	# the second will get the name assignments. This is because sometimes name assignments are put
	# in the IDC before the definitions are. Comments are also left to the second path, that way all
	# functions are created first.

	# Perform first sweep for definitions
	with open(file, 'rU') as f:
		for line in f:
			# Parse out definitions
			if "add_func" in line:
				startAddr 	= getBetween(line, "(0X", ",")
				endAddr 	= getBetween(line, "0X", ")")
				virtualAddr = int("0x" + startAddr, 16)

				# If the function hasn't already been defined by binja, we'll define it
				functionsAtAddr = binaryView.get_functions_containing(virtualAddr)

				if functionsAtAddr == None:
					
					binaryView.create_user_function(virtualAddr)

				# Sometimes IDA tab aligns the end address for some reason, so we'll split by the comma and strip the tab + "0X" prefix
				endAddr = endAddr.split(",")[1]
				endAddr = endAddr.replace("\t", "")
				endAddr = endAddr.replace(" ", "")
				endAddr = endAddr.replace("0X", "")

				functionList[startAddr] = SymbolDef(startAddr, endAddr)

			elif "create_strlit" in line:
				startAddr 	= getBetween(line, "(0X", ",")
				endAddr 	= getBetween(line, "0X", ")")

				# Sometimes IDA tab aligns the end address for some reason, so we'll split by the comma and strip the tab + "0X" prefix
				endAddr = endAddr.split(",")[1]
				endAddr = endAddr.replace("\t", "")
				endAddr = endAddr.replace(" ", "")
				endAddr = endAddr.replace("0X", "")

				stringDefList[startAddr] = SymbolDef(startAddr, endAddr)

	# Perform second sweep for names
	with open(file, 'rU') as f:
		for line in f:
			# Parse out name assignments
			if "set_name" in line:
				startAddr 	= getBetween(line, "(0X", ",")
				nameStr 	= getBetween(line, "\"", "\"")

				# Attempt to set the name on each list. We'll try strings first because they'll be the likeliest candidate.
				if startAddr in stringDefList:
					stringDefList[startAddr].setName(nameStr)
				elif startAddr in functionList:
					functionList[startAddr].setName(nameStr)

			elif "set_cmt" in line:
				startAddr 	= getBetween(line, "(0X", ",")
				commentTxt  = getBetween(line, "\"", "\"")

				if startAddr != "" and startAddr != None:
					commentList[startAddr] = CommentDef(startAddr, commentTxt)

	# Now define all the symbols via binja API
	for func in functionList:
		virtualAddr = int("0x" + functionList[func].start, 16)
		funcName 	= functionList[func].name
		binaryView.define_user_symbol(Symbol(SymbolType.DataSymbol, virtualAddr, funcName))

	for string in stringDefList:
		virtualAddr = int("0x" + stringDefList[string].start, 16)
		stringName  = stringDefList[string].name
		binaryView.define_user_symbol(Symbol(SymbolType.DataSymbol, virtualAddr, stringName))

	for cmt in commentList:
		virtualAddr = int("0x" + commentList[cmt].start, 16)
		commentTxt  = commentList[cmt].comment

		# Get the containing function for the comment
		commentFunctions = binaryView.get_functions_containing(virtualAddr)

		# In Binary Ninja, comments must be inside functions. In IDA, this isn't the case. We'll notify the user of this.
		if commentFunctions == None:
			if notifyUserNonFunctionComments == False:
				notifyUserNonFunctionComments = True
		else:
			commentFunc = commentFunctions[0]
			commentFunc.set_comment_at(virtualAddr, commentTxt)

	if notifyUserNonFunctionComments:
		show_message_box("Warning from IDC Importer", "The IDC file you imported contained comments that were outside of function definitions. " +
			"Binary Ninja does not allow this, so those comments have not been ported over.", MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.WarningIcon)

	show_message_box("IDC Import Successful", "Symbols from the IDC file have been successfully imported. ", MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.InformationIcon)

	return True, None

def importIDCInBackground(binaryView):
	# This is the string that's displayed in the pop-up dialogue by binja itself
	idcFile = OpenFileNameField("Import IDC")

	# Sets the title of the dialogue and gets the input field value
	get_form_input([idcFile], "IDC Import Options")

	file = None

	if idcFile.result != '':
		file = idcFile.result

	if len(idcFile.result) < 4:
		show_message_box("Error from IDC Importer", "The IDC file you've given is invalid. ", MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)
		return

	if idcFile.result[-4:] != ".idc":
		show_message_box("Error from IDC Importer", "The IDC file you've given is not a valid IDC file. ", MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)
		return

	# Pass the binaryview off to the background task handler
	backgroundTask = ImportIDCInBG(binaryView, file)
	backgroundTask.start()

# Registers the plugin with binja and allows us to specify the function that the binaryview is passed to.
PluginCommand.register("Import IDC File", "Import IDC dump from IDA", importIDCInBackground)