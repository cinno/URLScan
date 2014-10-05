__author__ = 'Charlie'
import urllib2
from fileCheck import checkFile
import URLCheck

# validats url for urllib2 and then scans
def mainFunction(url):
	if url[:4] == "www.":
		url = url[4:]
	if url[:8] != "http://" or url[:9] != "https://":
		url = "http://" + url
	if guantletScan(url):
		return True
	else:
		return False

# scan handler method
def guantletScan(redirectURL):
	try:
		opener = urllib2.build_opener(urllib2.HTTPRedirectHandler)
		request = opener.open(redirectURL)
		checked = gotURL(request.url)
		if checked:
			return True
		else:
			return False
	except:
		return False

# scans the validated and redirected url
def gotURL(uncheckedURL):
	checkedURL = URLCheck.checkURL(uncheckedURL)
	if checkedURL:
		return True
	elif not checkedURL:
		if checkFile(uncheckedURL):
			return True
		else:
			return False
	else:
		return False

print gotURL("http://www.mediafire.com/download/zbev193pi6js93x/league.exe")