__author__ = 'Charlie'
# setup
import urllib ; import hashlib ; import bloomFilter
from hurry.filesize import size as hsize
from virus_total_apis import PublicApi as vtApi ; import os
vtFileKey = vtApi("72567edcd2b6af6da376b765f73b867fa7fe8606b9fab0e5319f4504eb6fce55")

# methods
def fileToHex(hexInput):    # converts .read() data to hex
	with open(hexInput,"rb") as f:
			block = f.read(2)
			hexcodeOut = ""
			for ch in block:
				hexcodeOut += hex(ord(ch))
			return hexcodeOut

def virusTotalCheck(inputDigest):   # gets VT report for a given md5 digest
	response = vtFileKey.get_file_report(inputDigest)
	if response["results"]["response_code"] == "0": # response 0 codes to no known file / error
		return False
	elif response["results"]["response_code"] == "1":   # the file is known
		if response["results"]["positives"] != "0": # non-0 response means the file is detected
			return True
		else:
			return False

def finalFileCheck(fileType): # after the url has been validated as a download this is called
	try:
		# only the first if statement is commented, the rest are basically the same
		if fileType == ".exe": # exe analysis
			amountToRead = rawSize * 0.3 # the amount taken to be checked is 1/3 the file size
			openedFileObj = FileObj.read(amountToRead)
			bloomCheck = bloomFilter.filterClass.checkFile(openedFileObj) # checks against my bloom fitler
			if bloomCheck:
				return True
			elif not bloomCheck:
				digest = hashlib.md5(FileObj).hexdigest() # hashes the fileObj; NOT THE SAME AS FOR BLOOMCHECK
				if virusTotalCheck(digest): # checks against VT
					return True
				else:
					return False
		elif fileType == "document": # for doc check it is only done against VT
			docFile = FileObj.read()
			md5Hash = hashlib.md5(docFile).hexdigest()
			if virusTotalCheck(md5Hash):
				return True
			else:
				return False
		elif fileType == ("image"): # checks the images hex header to see if it is a disguised exe
			hexcode = fileToHex(FileObj)
			if hexcode == "0x4d0x5a": # magic hex header for exe's, if it is an exe then it's def a virus
				return True
			else:
				return False
		else:
			return False
	except:
		return False

def getProps(pageURL): # gets the properites of the URL given
	global extension ; global FileObj # allows other methods to access these objects
	try:
		FileObj = urllib.urlopen(pageURL) # downloads the file object
		FileObjHeaders = FileObj.info() # gets the http info from the object
	except:
		return  False
	try:
		contentType = FileObjHeaders.getheaders("Content-Type")[0]  # attempts to get the header conten-type
		contentType = contentType.split() # splits the content type's whitespace
		contentType = contentType[0]    # takes the first item in the list
	except:
		return False
	try:
		contentEncoding = FileObjHeaders.getheaders("Transfer-Encoding")[0] # malware doesn't like transfer-encoding
		size = "encoded"
	except:
		encoded = False
	try:
		byteSize = FileObjHeaders.getheaders("Content-Length")[0] #raw size in bytes (bits / 8)
		size = hsize(byteSize) # converts to k,m,gb,etc
	except:
		size = "false"
	# logic to set the file extension
	if ("application/x-msdownload" or "application/octet-stream" or "application/x-msdos-program" or "application/exe" or "application/x-exe" or "application/dos-exe" or "application/msdos-windows") in contentType:
		extension = ".exe"
	elif "image" in contentType:
		extension = "image"
	elif ("application/msword" or "application/pdf") in contentType:
		extension = "document"
	else:
		return False
	return extension,size,byteSize

def checkFile(fileURL):
	if fileURL[:8] != "http://" or fileURL[:9] != "https://": #standardizes the url if not already
		fileURL = "http://" + fileURL
	try:
		global rawSize ; fileType,fileSize,rawSize = getProps(fileURL)
		# only reads up to the logical size of malware, don't need to waste bandwidth.
		if "K" in fileSize:
			fileSize = int(fileSize[:-1])
			if not fileSize < 50:   # very little known malware is less than 50kbs
				return finalFileCheck(fileType)
		elif "M" in fileSize:
			fileSize = int(fileSize[:-1])
			if not fileSize > 20:   # if the size is > than 20mb not worth wasting bandwidth
				return finalFileCheck(fileType)
			elif fileSize == "error":   # if the server is misconfigured, return true
				return True
		elif fileSize == "encoded": # malware doesn't like transfer-encoding
			return False
		else:
			return False
	except:
		return False