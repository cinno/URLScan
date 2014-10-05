# setup
from bitarray import bitarray
from pyhashxx import hashxx
from spooky import hash64
import mmh3
from math import ceil
class bloomFilter():
	def __init__(self):
		global hashDatabase; hashDatabase = "database.txt"
		parsed = open(hashDatabase) ; parsed = parsed.read().splitlines()
		elements = int(len(parsed)) / 3
		global size ; size = int(ceil(-1 * ((elements * -2) / 0.48)))
		self.bit_array = bitarray(size)
		self.bit_array.setall(0)
		for line in parsed:
			value = int(line) % size
			self.bit_array[value] = 1

	def makeHashes(self,inp):
		self.inp = inp
		partial = []
		self.spooky = hash64(inp) % size
		partial.append(self.spooky)
		self.hashxx = hashxx(inp) % size
		partial.append(self.hashxx)
		self.mmh = abs(mmh3.hash(inp)) % size
		partial.append(self.mmh)
		return partial

	def addFile(self, raw):
		self.raw = raw
		hashed = self.makeHashes(raw)
		for x in hashed:
			self.bit_array[x] = 1

	def checkFile(self, raw):
		self.raw = open(raw)
		hashed = self.makeHashes(raw)
		for x  in hashed:
			if self.bit_array[x] == 0:
				return False
		return True
if __name__ == "__main__":  # initializes the bloom filter class on load of the script
	filterClass = bloomFilter()