import requests as r
import configparser
import subprocess
import argparse
import dataset
import json
import sys
import os
import io
import urllib.request
import struct
import tempfile
import fcntl
import zipfile as zip
import pdb

class autotss:

	def __init__(self, userPath = None):
		self.scriptPath = self.getScriptPath(userPath)
		self.liveFirmwareAPI = self.getFirmwareAPI()
		self.liveBetaAPI = self.getBetaAPI()
	
		self.database = dataset.connect('sqlite:///autotss.db')

		self.importNewDevices()
		self.checkBetaSigning()
		self.checkAllDevices()
		self.pushToDatabase()

	def open_remote_zip(self, url, offset=0):
		return urllib.request.urlopen(urllib.request.Request(url, headers={'Range': 'bytes={}-'.format(offset)}))

	def getFileOffset(self, firmware):
		""" Adapted from Karel Vlk's answer to a question on superuser.com """
		filearray = []
		offset = 0
		zipfile = self.open_remote_zip(firmware['url'])
		header = zipfile.read(30)
		while header[:4] == b'PK\x03\x04':
			compressed_len, uncompressed_len = struct.unpack('<II', header[18:26])
			filename_len, extra_len = struct.unpack('<HH', header[26:30])
			header_len = 30 + filename_len + extra_len
			total_len = header_len + compressed_len
			fn = zipfile.read(filename_len)
#			print('{}\n offset: {}\n length: {}\n  header: {}\n  payload: {}\n uncompressed length: {}'.format(fn, offset, total_len, header_len, compressed_len, uncompressed_len))
			filearray.append({'name': fn, 'offset': offset, 'total_len': total_len, 'header_len': header_len, 'compressed_len': compressed_len, 'uncompressed_len': uncompressed_len, 'EOF': offset + total_len}) 			
			if fn == b'AssetData/boot/BuildManifest.plist':
				cachepath = self.getManifest(firmware, filearray[-1])
				if self.scriptPath('verbose') == '1':
					print("Saved BuildManifest.plist in " + cachepath)
				break

			offset += total_len
			zipfile = self.open_remote_zip(firmware['url'], offset)
			header = zipfile.read(30)

		zipfile.close()
		return cachepath
		
	def getManifest(self, firmware, file):
		savePath = 'cache/' + firmware['deviceID'] + '/' + firmware['version'] + '/' + firmware['buildid']
		if not os.path.exists(savePath):
			os.makedirs(savePath)
		file2 = urllib.request.urlopen(urllib.request.Request(firmware['url'], headers={'Range': 'bytes={offset}-{EOF}'.format(**file)}))
		saveFile = tempfile.NamedTemporaryFile(suffix='.zip')
		saveFile.write(file2.read())
		saveFile.flush()
		file2.close()
		# will likely need to repair zip file since there is no central directory
		try:
			zipfile = zip.ZipFile(saveFile.name, 'r')
		except zip.BadZipFile:
			fixedZip = tempfile.NamedTemporaryFile(suffix='.zip')
			scriptArguments = ['zip',
				'-FF', saveFile.name, '--out', fixedZip.name]
			proc = subprocess.Popen(scriptArguments, stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=1)
			fcntl.fcntl(
				proc.stdout.fileno(),
				fcntl.F_SETFL,
				fcntl.fcntl(proc.stdout.fileno(), fcntl.F_GETFL) | os.O_NONBLOCK,
			)
			proc.communicate(b'y')
			zipfile = zip.ZipFile(fixedZip.name, 'r')			
			fixedZip.close()
		except:
			print("Could not get manifest for build " + firmware['buildid'] + ", iOS " + firmware['version'] + ", for " + firmware['deviceID'])
				
		fileout = savePath + '/BuildManifest.plist'
		f = open(fileout, 'wb')
		f.write(zipfile.read('AssetData/boot/BuildManifest.plist'))								
		f.close()
		zipfile.close()
		saveFile.close()
		
		return savePath

	def importNewDevices(self):
		""" Checks devices.txt for new entries. Parses entries and
		inserts them into the devices table in our database """

		print('\nChecking devices.ini for new devices...')
		db = self.database['devices']
		newDevices = []
		numNew = 0

		# Check to make sure devices.ini exists, otherwise warn and continue without new devices
		if os.path.isfile('devices.ini'):
			config = configparser.ConfigParser()
			config.read('devices.ini')
			for section in config.sections():
				name = section
				identifier = config.get(section, 'identifier').replace(' ','')
				ecid = config.get(section, 'ecid')

				try:
					boardconfig = config.get(section, 'boardconfig').lower()
				except:
					boardconfig = ''
				if not boardconfig:
					boardconfig = self.getBoardConfig(identifier)
					
				try:
					beta = config.get(section, 'beta').replace(' ','')
				except:
					beta = 0

				newDevices.append({'deviceName': name, 'deviceID': identifier, 'boardConfig': boardconfig, 'deviceECID': ecid, 'blobsSaved': '[]', 'beta': beta})
		else:
			print('Unable to find devices.ini')

		# Add only new devices to database
		for newDevice in newDevices:
			if not db.find_one(deviceECID=newDevice['deviceECID']):
				print('Device: [{deviceName}] ECID: [{deviceECID}] Board Config: [{boardConfig}]'.format(**newDevice))
				numNew += 1
				db.insert(newDevice)
		if numNew == 0:
			print('No new devices found in devices.ini.')
		else:
			print('Added {} new devices to the database'.format(str(numNew)))
		return

	def getBoardConfig(self, deviceID):
		""" Using the IPSW.me API, when supplied a device identifier
		the relevant board config will be returned."""

		return self.liveFirmwareAPI[deviceID]['BoardConfig']

	def checkForBlobs(self, deviceECID, buildID):
		""" Checks against our database to see if blobs for a
		device have already been saved for a specific iOS version.
		The device is identified by a deviceECID, iOS version is
		identified by a buildID. """

		deviceInfo = self.database['devices'].find_one(deviceECID=deviceECID)

		for entry in json.loads(deviceInfo['blobsSaved']):
			if entry['buildID'] == buildID:
				return True

		return False

	def getFirmwareAPI(self):
		""" Taking the raw response from the IPSW.me API, process
		 the response as a JSON object and remove unsigned firmware
		 entries. Returns a freshly processed devices JSON containing
		 only signed firmware versions. """

		headers = {'User-Agent': 'Script to automatically save shsh blobs (https://github.com/codsane/autotss)'}

		rawResponse = r.get('https://api.ipsw.me/v2.1/firmwares.json/condensed', headers=headers)

		deviceAPI = rawResponse.json()['devices']

		''' Rather than messing around with copies, we can loop
		 through all firmware dictionary objects and append the
		 signed firmware objects to a list. The original firmware
		 list is then replaced with the new (signed firmware only) list.'''
		print('Checking IPSW.me for signing status for released IOS versions.')
		for deviceID in deviceAPI:
			signedFirmwares = []
			for firmware in deviceAPI[deviceID]['firmwares']:
				if firmware['signed']:
					signedFirmwares.append(firmware)
			deviceAPI[deviceID]['firmwares'] = signedFirmwares
		return deviceAPI

	def getBetaAPI(self):
		""" Taking the raw response from the IPSW.me OTA API, process
		 the response as a JSON object and select relevant builds.
		 Returns a freshly processed devices JSON containing only
		 beta firmware versions with no prerequisites. """

		headers = {'User-Agent': 'Script to automatically save shsh blobs (https://github.com/codsane/autotss)'}

		rawResponse = r.get('https://api.ipsw.me/v2.1/ota.json/condensed', headers=headers)

		betaAPI = rawResponse.json()

		''' Rather than messing around with copies, we can loop
		 through all firmware dictionary objects and append the
		 signed firmware objects to a list. The original firmware
		 list is then replaced with the new (signed firmware only) list.'''
		for deviceID in betaAPI:
			betaFirmwares = []
			for firmware in betaAPI[deviceID]['firmwares']:
				try:
					releasetype = firmware['releasetype']
					firmware['boardConfig'] = betaAPI[deviceID]['BoardConfig']
				except:
					releasetype = ''
				if releasetype == 'Beta':
					try:
						prereq = firmware['prerequisiteversion']
					except:
						prereq = ''
					if not prereq:
						betaFirmwares.append(firmware)
			betaAPI[deviceID]['firmwares'] = betaFirmwares

		return betaAPI

	def checkBetaBuildSigning(self, firmware):
		""" Call tsschecker to check signing status of a beta OTA firmware. Update database
		with results. """
		if self.scriptPath['cache'] == 1:
			scriptArguments = [self.scriptPath['path'],
						'-d', firmware['deviceID'],
						'-m', firmware['cachepath'] + '/BuildManifest.plist',
						'--buildid', firmware['buildid'],
						'-B', firmware['boardConfig'],
						'-o', '--beta']
		else:
			scriptArguments = [self.scriptPath['path'],
						'-d', firmware['deviceID'],
						'--buildid', firmware['buildid'],
						'-B', firmware['boardConfig'],
						'-o', '--beta']
								
		if self.scriptPath['verbose'] == '1':
			print('Checking signing status for {buildid} for {deviceID}, {boardConfig}'.format(**firmware))
		tssCall = subprocess.Popen(scriptArguments, stdout=subprocess.PIPE)

		tssOutput = []
		for line in io.TextIOWrapper(tssCall.stdout, encoding='utf-8'):
			tssOutput.append(line.strip())

		''' Checks console output for the `IS being signed!`
		string. While this works for now, tsschecker updates
		may break the check. '''
		if 'Build {buildid} for device {deviceID} IS being signed!'.format(**firmware) in tssOutput:
			sqlquery = "update beta set signed = '1' where deviceID = '" + firmware['deviceID'] + "' and buildid = '" + firmware['buildid'] + "' and boardConfig = '" + firmware['boardConfig'] + "'"
			self.database.query(sqlquery)
			if self.scriptPath['verbose'] == '1':
				print('{buildid} is being signed for {deviceID}, {boardConfig}'.format(**firmware))
		elif 'Build {buildid} for device {deviceID} IS NOT being signed!'.format(**firmware) in tssOutput:
			sqlquery = "update beta set signed = '0' where deviceID = '" + firmware['deviceID'] + "' and buildid = '" + firmware['buildid'] + "' and boardConfig = '" + firmware['boardConfig'] + "'"
			self.database.query(sqlquery)
			if self.scriptPath['verbose'] == '1':
				print('{buildid} is NOT being signed for {deviceID}, {boardConfig}'.format(**firmware))
		else:
			sqlquery = "update beta set signed = '2' where deviceID = '" + firmware['deviceID'] + "' and buildid = '" + firmware['buildid'] + "' and boardConfig = '" + firmware['boardConfig'] + "'"
			self.database.query(sqlquery)
			if self.scriptPath['verbose'] == '1':
				print('{buildid} signing status for {deviceID}, {boardConfig} could not be determined. Will try again next time.'.format(**firmware))
				print('Output from tsschecker: ')
				for line in tssOutput:
					print(line)
		return
		
	def checkBetaSigning(self):
		""" Loop through firmwares downloaded from IPSW and determine which are currently
		 being signed by checking local database or by brute-force if --betarefresh is
		 specified. """
		
		db = self.database['beta']
		beta = []
		numNew = 0
		
		""" We only want to check beta firmwares for the devices in our db """
		ourDevices = self.database['devices'].distinct('deviceID')
	
		print('Checking signing status for beta OTA updates.')

		for row in ourDevices:
#			print(row['deviceID'])
			betaFirm = self.liveBetaAPI[row['deviceID']]['firmwares']
			for firmware in betaFirm:
				beta.append({'boardConfig': firmware['boardConfig'], 'signed': '2', 'buildid': firmware['buildid'], 'deviceID': row['deviceID'], 'version': firmware['version'], 'url': firmware['url'], 'cached': '0', 'cachepath': ''})

		# Add new betafirmwares to database
		for newBeta in beta:
			if not db.find_one(deviceID=newBeta['deviceID'],buildid=newBeta['buildid']):
				if self.scriptPath['verbose']:
					print('DeviceID: [{deviceID}] Build ID: [{buildid}]'.format(**newBeta))
				numNew += 1
				db.insert(newBeta)
		if numNew == 0:
			print('Beta firmware database is up to date.')
		else:
			print('Added {} new beta firmwares to the database'.format(str(numNew)))

		
		""" Check betarefresh flag and set signed status to unknown to refresh """
		if self.scriptPath['betarefresh'] == 1:
			self.database.query('update beta set signed = 2')
			print("Beta signing status set to unknown for all beta firmwares.\n")
			
		""" Check resetcache flag and clear cached flag from beta table """
		if self.scriptPath['resetcache'] == 1:
			self.database.query('update beta set cached = 0 and cachepath = null')
			print("Buildmanifest cache status has been reset.\n")
			
		""" If cache flag set, download buildmanifest files and set cached status in beta table """
		if self.scriptPath['cache'] == 1:
			print("Checking for cached BuildManifest.plist files and downloading if needed.")
			betaFW = [row for row in db]
			for FW in betaFW:
				if FW['cached'] == '0':
					if not os.path.isfile(FW['cachepath'] + "/BuildManifest.plist"):
						cachepath = self.getFileOffset(FW)
						sqlquery = "update beta set cached = '1', cachepath = '" + cachepath + "' where deviceID = '" + FW['deviceID'] + "' and buildid = '" + FW['buildid'] + "' and boardConfig = '" + FW['boardConfig'] + "'"
						self.database.query(sqlquery)
								
		
		""" Iterate through beta firmwares and call routine to check signing status if needed.
		Unsigned = 0, signed = 1, unknown = 2 """
		betaFW = [row for row in db]
		for FW in betaFW:
			if FW['signed'] == '2':
				if self.scriptPath['verbose'] == '1':
					print("Need to get signing status for IOS {version}:{buildid}, device {deviceID}, boardconfig {boardConfig}.".format(**FW))
				self.checkBetaBuildSigning(FW)
		return
			
	def checkAllDevices(self):
		""" Loop through all of our devices and grab matching
		device firmwares from the firmwareAPI. Device and
		firmware info is sent to saveBlobs(). """

		print('\nGrabbing devices from the database...')
		self.devices = [row for row in self.database['devices']]
		for device in self.devices:
			print('Device: [{deviceName}] ECID: [{deviceECID}] Board Config: [{boardConfig}]'.format(**device))
		print('Grabbed {} devices from the database'.format(len(self.devices)))


		print('\nSaving unsaved blobs for {} devices...'.format(str(len(self.devices))))
		for device in self.devices:
			for firmware in self.liveFirmwareAPI[device['deviceID']]['firmwares']:
				self.saveBlobs(device, firmware['buildid'], firmware['version'])

			""" Check for beta blobs if beta flag set for device """
			if device['beta'] == 1:
				print("Beta enabled for device {}.".format(device['deviceECID']))
				
				for firmware in self.database['beta'].find(deviceID=device['deviceID']):
					if firmware['signed'] == '1':
						self.saveBetaBlobs(device, firmware['buildid'], firmware['version'], firmware['cachepath'])
		print('Done saving blobs')

	def saveBlobs(self, device, buildID, versionNumber):
		""" First, check to see if blobs have already been
		saved. If blobs have not been saved, use subprocess
		to call the tsschecker script and save blobs. After
		saving blobs, logSavedBlobs() is called to log that
		we saved the device/firmware blobs. """

		if self.checkForBlobs(device['deviceECID'], buildID):
			# print('[{0}] [{1}] {2}'.format(device['deviceID'], versionNumber, 'Blobs already saved!'))
			return

		savePath = 'blobs/' + device['deviceID'] + '/' + device['deviceECID'] + '/' + versionNumber + '/' + buildID
		if not os.path.exists(savePath):
			os.makedirs(savePath)

		scriptArguments = [self.scriptPath['path'],
						'-d', device['deviceID'],
						'-e', device['deviceECID'],
						'--boardconfig', device['boardConfig'],
						'--buildid', buildID,
						'--save-path', savePath,
						'-s']

		tssCall = subprocess.Popen(scriptArguments, stdout=subprocess.PIPE)

		tssOutput = []
		for line in io.TextIOWrapper(tssCall.stdout, encoding='utf-8'):
			tssOutput.append(line.strip())

		''' Checks console output for the `Saved shsh blobs!`
		string. While this works for now, tsschecker updates
		may break the check. It may be possible to check to
		see if the .shsh file was created and also check for
		the right file format. '''
		if 'Saved shsh blobs!' in tssOutput:
			self.logBlobsSaved(device, buildID, versionNumber)
			print('[{0}] [{1} - {2}] {3}'.format(device['deviceName'], versionNumber, buildID, 'Saved shsh blobs!'))
		else:
			self.logBlobsFailed(scriptArguments, savePath, tssOutput)
			print('[{0}] [{1} - {2}] {3}'.format(device['deviceName'], versionNumber, buildID, 'Error, see log file: ' + savePath + '/tsschecker_log.txt'))

		return

	def saveBetaBlobs(self, device, buildID, versionNumber, cachepath):
		""" First, check to see if blobs have already been
		saved. If blobs have not been saved, use subprocess
		to call the tsschecker script and save blobs. After
		saving blobs, logSavedBlobs() is called to log that
		we saved the device/firmware blobs. """

		if self.checkForBlobs(device['deviceECID'], buildID):
			# print('[{0}] [{1}] {2}'.format(device['deviceID'], versionNumber, 'Blobs already saved!'))
			return

		savePath = 'blobs/' + device['deviceID'] + '/' + device['deviceECID'] + '/' + versionNumber + '/' + buildID
		if not os.path.exists(savePath):
			os.makedirs(savePath)

		if self.scriptPath['cache'] == 1:
			scriptArguments = [self.scriptPath['path'],
						'-d', device['deviceID'],
						'-m', cachepath + '/BuildManifest.plist',
						'-e', device['deviceECID'],
						'--boardconfig', device['boardConfig'],
						'--buildid', buildID,
						'--save-path', savePath,
						'-s', '-o', '--beta']
		else:
			scriptArguments = [self.scriptPath['path'],
						'-d', device['deviceID'],
						'-e', device['deviceECID'],
						'--boardconfig', device['boardConfig'],
						'--buildid', buildID,
						'--save-path', savePath,
						'-s', '-o', '--beta']		
		
		tssCall = subprocess.Popen(scriptArguments, stdout=subprocess.PIPE)

		tssOutput = []
		for line in io.TextIOWrapper(tssCall.stdout, encoding='utf-8'):
			tssOutput.append(line.strip())

		''' Checks console output for the `Saved shsh blobs!`
		string. While this works for now, tsschecker updates
		may break the check. It may be possible to check to
		see if the .shsh file was created and also check for
		the right file format. '''
		if 'Saved shsh blobs!' in tssOutput:
			self.logBetaBlobsSaved(device, buildID, versionNumber)
			print('[{0}] [{1} - {2}] {3}'.format(device['deviceName'], versionNumber, buildID, 'Saved shsh blobs!'))
		else:
			self.logBlobsFailed(scriptArguments, savePath, tssOutput)
			print('[{0}] [{1} - {2}] {3}'.format(device['deviceName'], versionNumber, buildID, 'Error, see log file: ' + savePath + '/tsschecker_log.txt'))

		return

	def logBlobsSaved(self, device, buildID, versionNumber):
		""" Taking a reference to a device dictionary, we can
		 load the string `blobsSaved` from the database into
		 a JSON object, append a newly saved version, and
		 turn the JSON object back into a string and
		 replace `blobsSaved` """

		oldBlobsSaved = json.loads(device['blobsSaved'])
		newBlobsSaved = {'releaseType': 'release', 'versionNumber': versionNumber, 'buildID': buildID}

		oldBlobsSaved.append(newBlobsSaved)

		device['blobsSaved'] = json.dumps(oldBlobsSaved)

		return

	def logBetaBlobsSaved(self, device, buildID, versionNumber):
		""" Taking a reference to a device dictionary, we can
		 load the string `blobsSaved` from the database into
		 a JSON object, append a newly saved version, and
		 turn the JSON object back into a string and
		 replace `blobsSaved` """

		oldBlobsSaved = json.loads(device['blobsSaved'])
		newBlobsSaved = {'releaseType': 'beta', 'versionNumber': versionNumber, 'buildID': buildID}

		oldBlobsSaved.append(newBlobsSaved)

		device['blobsSaved'] = json.dumps(oldBlobsSaved)

		return

	def logBlobsFailed(self, scriptArguments, savePath, tssOutput):
		""" When blobs are unable to be saved, we save
		a log of tsschecker's output in the blobs folder. """

		with open(savePath + '/tsschecker_log.txt', 'w') as file:
			file.write(' '.join(scriptArguments) + '\n\n')
			file.write('\n'.join(tssOutput))

		return

	def pushToDatabase(self):
		""" Loop through all of our devices and update their
		entries into the database. ECID is used as the value
		to update by, as it is the only unique device identifier."""

		print('\nUpdating database with newly saved blobs...')
		for device in self.devices:
			self.database['devices'].update(device, ['deviceECID'])
		print('Done updating database')

		return

	def getScriptPath(self, userPath):
		""" Determines if the user provided a path to the tsschecker
		 binary, whether command line argument or passed to autotss().
		 If the user did not provide a path, try to find it within
		 /tsschecker or /tsschecker-latest and select the proper binary
		 Also verifies that these files exist. """
		 
		""" Added routine to capture argument to force refresh of beta signing database.
		 Now returns a dictionary object with path and betarefresh keys. """

		scriptPath = {}

		argParser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
		argParser.add_argument("-p", "--path", help='Supply the path to your tsschecker binary.\nExample: -p /Users/codsane/tsschecker/tsschecker_macos', required=False, default='')
		argParser.add_argument("-b", "--betarefresh", action='store_const', const=1, help='Force a refresh of the beta firmware signing database.', required=False, default='0')
		argParser.add_argument("-c", "--cache", action='store_const', const=1, help='Use the buildmanifest cache to save time.', required=False, default='1')
		argParser.add_argument("-r", "--resetcache", action='store_const', const=1, help='Refresh the buildmanifest cache.', required=False, default='0')
		argParser.add_argument("-v", "--verbose", action='store_const', const=1, help='Verbose output.', required=False, default='0')
		argument = argParser.parse_args()

		# Check to see if the user provided the command line argument -p or --path
		if argument.path:
			scriptPath['path'] = argument.path

			# Check to make sure this file exists
			if os.path.isfile(argument.path):
				print('Using manually specified tsschecker binary: ' + argument.path)
			else:
				print('Unable to find tsschecker at specificed path: ' + argument.path)
				sys.exit()

		# No command line argument provided, check to see if a path was passed to autotss()
		else:
			scriptPath['path'] = "./tsschecker"

		try:
			tssCall = subprocess.Popen(scriptPath['path'], stdout=subprocess.PIPE)
		except subprocess.CalledProcessError:
			pass
		except OSError:
			print('tsschecker not found. Install or point to with -p')
			print('Get tsschecker here: https://github.com/encounter/tsschecker/releases')
			sys.exit()


		# Check to make sure user has the right tsschecker version
		tssOutput = []
		for line in io.TextIOWrapper(tssCall.stdout, encoding='utf-8'):
			tssOutput.append(line.strip())

		versionNumber = int(tssOutput[0].split('-')[-1].strip())
		if versionNumber < 247:
			print('Your version of tss checker is too old')
			print('Get the latest version here: http://api.tihmstar.net/builds/tsschecker/tsschecker-latest.zip')
			print('Unzip into the same folder as autotss')
			sys.exit()
	
		if argument.betarefresh:
			scriptPath['betarefresh'] = argument.betarefresh
		scriptPath['cache'] = argument.cache
		scriptPath['resetcache'] = argument.resetcache
		scriptPath['verbose'] = argument.verbose
		
		return scriptPath

def main():
	# autotss('/Users/codsane/tsschecker/tsschecker_macos')
	autotss()

if __name__ == "__main__":
	main()