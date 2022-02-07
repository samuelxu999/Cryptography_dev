'''
========================
efficient_vrf module
========================
Created on Feb.6, 2022
@author: Xu Ronghua
@Email:  rxu22@binghamton.edu
@TaskDescription: This module provide efficient verifiable delay function implementation.
@Reference: Efficient Verifiable Delay Functions (By Wesolowski)
			C++ prototype: https://github.com/iotaledger/vdf/tree/master/src

'''
import os
import time
import hashlib
import gmpy2
from gmpy2 import mpz

'''
===================== Internal functions ========================
'''
## integer to hex
def int_to_hex(int_data):
	return hex(int_data)
	
## hex to integer
def hex_to_int(hex_data):
	return int(hex_data, 16)


'''
======================= Efficient VDF class ========================
'''
class E_VDF(object):
	def __init__(self, _lambda, _k, seed_type=0):
		'''
		Initialize parameters:
		_lambda:	This is used to generate RSA prime N with ength p_lambda/2
		_k:			Security parameter _k defines length of hash string l.
		r_state:	Random state is used to generate prime.
		'''

		self._lambda = _lambda
		## set security parameter _k that defines length of hash string.
		self._k = _k


		if(seed_type ==1):
			## 1) use random number as seed
			r_seed = int(os.urandom(32).hex(), 16)
		else:
			## 2) use hash of random_state as seed
			r_seed = hash(gmpy2.random_state())

		## create random state
		self.r_state = gmpy2.random_state(r_seed)

	@staticmethod
	def generate_prime(r_state, bitLen):
		'''
		generate a random prime number
		@Input:
			r_state: generate by gmpy2.random_state(r_seed)
		    bitLen: bit length of the prime number
		@Output:
		    mpz_prime: an uniformly distributed random integer between 0 and 2**bitLen - 1

		'''
		mpz_random = gmpy2.mpz_urandomb(r_state, bitLen)	

		mpz_prime = gmpy2.next_prime(mpz_random)
		
		return mpz_prime

	def hash_prime(self, mpz_prime):
		'''
		generate a next_prime given the output of H(current_prime)
		@Input:
		    mpz_prime: current mpz_prime used to calculate hash_prime
		@Output:
		    next_mpz_prime (l): the closet prime number to H(mpz_prime)
		'''

		## 1) convert mpz_prime to hex format
		hex_mpz_prime = int_to_hex(mpz_prime)

		## 2) get hex format hash value that is output of H(mpz_prime)
		if(self._k==128):
			hash_data = hashlib.sha256(hex_mpz_prime.encode('utf-8')).hexdigest()
		else:
			hash_data = hashlib.sha1(hex_mpz_prime.encode('utf-8')).hexdigest()

		## 3) convert hash_data to mpz format
		hash_mpz_prime = mpz(hex_to_int(hash_data))
		
		## 4) get next prime that is closed to hash_mpz_prime
		next_mpz_prime = gmpy2.next_prime(hash_mpz_prime)
		return next_mpz_prime










