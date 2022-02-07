'''
========================
test_main.py
========================
Created on Feb.05, 2022
@author: Xu Ronghua
@Email:  rxu22@binghamton.edu
@TaskDescription: This is used to unit function test and demo.
@Reference: 
'''

import sys
import time
import random
import logging
import argparse
import functools

from cryptolib.crypto_rsa import Crypto_RSA
from PVSS.rsa_pvss import PVSS, _RINT 
from VRF.rsa_vrf import RSA_PublicKey, RSA_PrivateKey, RSA_FDH_VRF
from VDF.efficient_vdf import E_VDF

logger = logging.getLogger(__name__)

def get_public_numbers_from_files():
	#define public numbers
	key_numbers={}
	load_public_key_bytes = Crypto_RSA.load_key_bytes('public_key_file')

	reload_publick_key=Crypto_RSA.load_public_key(load_public_key_bytes)

	# genereate key pairs numbers
	public_numbers = reload_publick_key.public_numbers()

	# add public numbers
	key_numbers['n']=public_numbers.n
	key_numbers['e']=public_numbers.e
	key_numbers['key_size']=reload_publick_key.key_size

	return key_numbers

def get_key_numbers_from_files():
	#define key_pairs dictionary
	key_numbers={}
	load_public_key_bytes = Crypto_RSA.load_key_bytes('public_key_file')
	load_private_key_bytes = Crypto_RSA.load_key_bytes('private_key_file')

	reload_publick_key=Crypto_RSA.load_public_key(load_public_key_bytes)
	#print(reload_publick_key.public_numbers())

	reload_private_key=Crypto_RSA.load_private_key(load_private_key_bytes, 'samuelxu999')
	#print(reload_private_key.private_numbers().d)

	# genereate key pairs numbers
	private_numbers = reload_private_key.private_numbers()
	public_numbers = reload_publick_key.public_numbers()

	#add private key value - x
	key_numbers['n']=public_numbers.n
	key_numbers['e']=public_numbers.e
	key_numbers['d']=private_numbers.d
	key_numbers['key_size']=reload_private_key.key_size

	return key_numbers

def rsa_test(args):
	## 1) generate key number
	keys_numbers = Crypto_RSA.generate_key_numbers()
	logger.info('Create key pairs: {}\n'.format(keys_numbers))

	##) 2) publish {Pk, Sk} pairs
	publick_key = Crypto_RSA.get_public_key(keys_numbers['n'], keys_numbers['e'])
	logger.info('public key: {}'.format(publick_key.public_numbers()))

	private_key = Crypto_RSA.get_private_key(keys_numbers['n'], keys_numbers['e'], keys_numbers['d'])
	logger.info('private key: {}\n'.format(private_key.private_numbers().d))

	##) 3) Convert key pairs to byte format that are convenient to transimit and save
	public_key_bytes = Crypto_RSA.get_public_key_bytes(publick_key)
	logger.info('public key bytes: {}'.format(public_key_bytes))

	private_key_bytes = Crypto_RSA.get_private_key_bytes(private_key, 'samuelxu999')
	logger.info('private key bytes: {}\n'.format(private_key_bytes))

	##) 4) Rebuild key pairs based on byte format key data 
	load_publick_key = Crypto_RSA.load_public_key(public_key_bytes)
	logger.info('Rebuild public key from bytes: {}'.format(load_publick_key.public_numbers()))

	load_private_key = Crypto_RSA.load_private_key(private_key_bytes, 'samuelxu999')
	logger.info('Rebuild private key from bytes: {}\n'.format(load_private_key.private_numbers().d))

	## 5) save key pairs to local file
	Crypto_RSA.save_key_bytes(public_key_bytes, 'public_key_file')
	Crypto_RSA.save_key_bytes(private_key_bytes, 'private_key_file')
	
	## 6) reload key pairs from local file
	load_public_key_bytes = Crypto_RSA.load_key_bytes('public_key_file')
	load_private_key_bytes = Crypto_RSA.load_key_bytes('private_key_file')

	reload_publick_key = Crypto_RSA.load_public_key(load_public_key_bytes)
	logger.info('Reload public key from local ke file: {}'.format(reload_publick_key.public_numbers()))

	reload_private_key = Crypto_RSA.load_private_key(load_private_key_bytes, 'samuelxu999')
	logger.info('Reload private number from local key file: {}\n'.format(reload_private_key.private_numbers().d))

	## 7) sign message and verificaion test
	## sing message
	if(args.message==''):
		message_data = 'This is text to test RSA sign.'
	else:
		message_data = args.message
	sign_value = Crypto_RSA.sign(reload_private_key, message_data)
	logger.info('Sign message: {} \t signature: {}'.format(message_data, sign_value))

	## 8) message encrypt and decrypt test
	## verify signature
	verify_sign=Crypto_RSA.verify(reload_publick_key,sign_value,message_data)
	logger.info('Signature verification: {}\n'.format(verify_sign))

	## encryption
	if(args.message==''):
		message_data = 'This is text to test RSA encrypt.'
	else:
		message_data = args.message
	cipher_text = Crypto_RSA.encrypt(reload_publick_key, message_data)
	logger.info('Encrypt message: {} \t cipher: {}'.format(message_data, cipher_text))

	#decryption
	plain_text = Crypto_RSA.decrypt(reload_private_key, cipher_text)
	logger.info('Decrypt cipher text and and verify: {}'.format(plain_text == message_data))

def pvss_test(args):
	## default prime number
	PRIME_EXP = 65537
	
	## choose RSA key source 0: From RSA key generator; 1:From saved key_bytes files
	RSA_key_src = args.op_status

	## 1) get key numbers
	if(RSA_key_src==0):
		## a) From RSA key generator
		keys_numbers = Crypto_RSA.generate_key_numbers(PRIME_EXP, 512)
		logger.info('Create new key for test.')
	else:
		## b) From saved key_bytes files
		keys_numbers = get_public_numbers_from_files()
		logger.info('Reload key from local files.')
	
	logger.info('Key numbers: {}\n'.format(keys_numbers))

	## 2) parameters configuration
	## set p and e
	p = keys_numbers['n']
	e = PRIME_EXP

	## poly parameter size should be no more than key_size/2
	poly_max = pow(2, (keys_numbers['key_size']/2) )-1
	s = _RINT(poly_max)
	t = args.vss_t
	n = args.vss_n
	
	logger.info('PVSS parameters: t-{} n-{}\n'.format(t,n))

	'''=============== test PVSS function ======================='''
	poly_secrets, shares = PVSS.split_shares(s, t, n, poly_max, p)
	logger.info('Create poly secret:')
	if poly_secrets:
		for poly_secret in poly_secrets:
			logger.info('{}'.format(poly_secret))	
	logger.info('')      
	
	logger.info('Create shares:')
	if shares:
	    for share in shares:
	        logger.info('{}'.format(share))
	logger.info('')   

	# Use e as G to construct commitment and verification
	poly_commits = PVSS.get_poly_commitment(e, poly_secrets, p)
	logger.info('Create poly_commitments:')
	if poly_commits:
	    for poly_commit in poly_commits:
	        logger.info('{}'.format(poly_commit))
	logger.info('') 

	share_proofs = PVSS.get_share_proofs(e, shares, p)
	logger.info('Create share_proofs:')
	if share_proofs:
	    for share_proof in share_proofs:
	        logger.info('{}'.format(share_proof))
	logger.info('')

	verify_shares = PVSS.verify_shares(poly_commits, share_proofs, p)
	logger.info('Create verify_shares:')
	if verify_shares:
	    for verify_share in verify_shares:
	        logger.info('{}'.format(verify_share))
	logger.info('')

	logger.info('Compair if share_proofs==verify_shares:')
	if verify_shares:
	    for share_proof, verify_share in zip(share_proofs, verify_shares):
	        logger.info('({}, {})'.format(share_proof[0],share_proof == verify_share))
	logger.info('')

	verify_S0 = PVSS.verify_S0(poly_commits, p)
	logger.info('Verify S0:{}'.format(verify_S0 == poly_commits[0]))

# this function show basic VSS function.
def VSS_demo(args):
	## default prime number
	_PRIME = 2**511 - 1
	PRIME_EXP = 65537
	
	## 1) key numbers generation
	keys_numbers = Crypto_RSA.generate_key_numbers(PRIME_EXP, 512)

	## 2) parameters configuration
	p = keys_numbers['n']
	s = _RINT(_PRIME)
	poly_max = _PRIME
	t = args.vss_t
	n = args.vss_n
	
	## 3) create (t,n) shares
	secret, shares = PVSS.split_shares(s, t, n, poly_max, p)
	logger.info('Create ({}, {}) secret shares.\n'.format(t,n))

	logger.info('secret S0:{}\n'.format(secret[0]))
	
	logger.info('shares:')
	if shares:
	    for share in shares:
	        logger.info('{}'.format(share))
	logger.info('')

	logger.info('secret recovered from subset of {} shares: {}\n'.format(t,
	      PVSS.recover_secret(shares[:t], p)))

	logger.info('secret recovered from different subset of {} shares: {}'.format(t,
	      PVSS.recover_secret(shares[-(t):], p)))

def vrf_test(args):
	if(args.message==''):
		alpha = "This text for vrf test."
	else:
		alpha = args.message

	logger.info('Test message: {}'.format(alpha))

	## choose RSA key source 0: From RSA key generator; 1:From saved key_bytes files
	RSA_key_src = args.op_status

	## 1) get key numbers
	if(RSA_key_src==0):
		## a) From RSA key generator
		keys_numbers = Crypto_RSA.generate_key_numbers(65537, 2048)
		logger.info('Create new key for test.\n')
	else:
		## b) From saved key_bytes files
		keys_numbers = get_key_numbers_from_files()
		logger.info('Reload key from local files.\n')

	## use key number to create RSA_PublicKey() and RSA_PrivateKey() instances
	rsa_publickey = RSA_PublicKey(keys_numbers['n'], keys_numbers['e'])
	rsa_privatekey = RSA_PrivateKey(keys_numbers['n'], keys_numbers['d'])

	## k should be no less than key_size/8
	k = int(keys_numbers['key_size']/8)

	## 2) generate proof pi
	pi = RSA_FDH_VRF.prove(rsa_privatekey, alpha, k)
	logger.info('Generate proof pi: {}\n'.format(pi))

	## 3) generate hash value v using default SHA1
	beta = RSA_FDH_VRF.proof2hash(pi)
	logger.info('Generate hash value beta: {}\n'.format(beta))

	## convert beta to integer that is useful to verify process.
	os2ip = RSA_FDH_VRF.os2ip(beta)
	logger.info('os2ip-convert beta to integer: {}\n'.format(os2ip))

	## As proof2hash uses SHA1, thus Xlen= len(SHA)/8=20 
	i2osp = RSA_FDH_VRF.i2osp(os2ip, 20)
	logger.info('i2osp-convert integer back to beta: {}\n'.format(i2osp))

	isValid = RSA_FDH_VRF.verifying(rsa_publickey, alpha, pi, k)
	logger.info('Verify proof: {}'.format(isValid))

def vdf_test(args):
	## initialize E_VDF instance eVDF
	eVDF=E_VDF()

	ls_time = []
	int_lambda =  args.lam
	int_k = args.k
	int_tau_exp = 2**args.tau

	## 1) set_up process
	start_time=time.time()	
	mpz_N = eVDF.set_up(int_lambda, int_k)
	exec_time=time.time()-start_time
	ls_time.append(exec_time)
	logger.info('eVDF set_up: lambda: {} \t k: {} \t N: {}\n'.format(eVDF._lambda, eVDF._k, mpz_N))

	## 2) evaluate and proof process
	if(args.message==''):
		x = "This text for vdf test."
	else:
		x = args.message

	logger.info('Test message: {}'.format(x))
	start_time=time.time()	
	proof_pair = eVDF.evaluate_proof(x, int_tau_exp, mpz_N)
	exec_time=time.time()-start_time
	ls_time.append(exec_time)
	logger.info('eVDF evaluate_proof: tau_exp-2^{}\t pi: {} \t l: {}\n'.format(args.tau, proof_pair[0], proof_pair[1]))

	## 2) verify proof process
	start_time=time.time()
	proof_verify = eVDF.verify_proof(x, int_tau_exp, mpz_N, proof_pair)
	exec_time=time.time()-start_time
	ls_time.append(exec_time)
	logger.info('eVDF verify_proof: tau_exp-2^{}\t result: {}\n'.format(args.tau, proof_verify))

	logger.info('Exec time: {}\n'.format(ls_time))

def define_and_get_arguments(args=sys.argv[1:]):
	parser = argparse.ArgumentParser(description="Run test.")

	parser.add_argument("--test_func", type=int, default=0, 
						help="Execute test function: 0-rsa_test(), \
													1-pvss_test() \
													2-VSS_demo() \
													3-vrf_test() \
													4-vdf_test()")

	parser.add_argument("--op_status", type=int, default=0, help="test case type.")

	parser.add_argument("--message", type=str, default="", 
						help="Test message text.")

	parser.add_argument("--vss_t", type=int, default=3, help="t value in VSS.")

	parser.add_argument("--vss_n", type=int, default=6, help="n value in VSS.")

	parser.add_argument("--lam", type=int, default=256, help="lambda in VDF.")

	parser.add_argument("--k", type=int, default=128, help="k in VDF.")

	parser.add_argument("--tau", type=int, default=20, help="t in in VDF.")

	args = parser.parse_args(args=args)
	return args

if __name__ == '__main__':
	FORMAT = "%(asctime)s %(levelname)s | %(message)s"
	LOG_LEVEL = logging.INFO
	logging.basicConfig(format=FORMAT, level=LOG_LEVEL)

	## initialize arguments
	args = define_and_get_arguments()

	## execute functions based on arguments
	if(args.test_func==1):
		pvss_test(args)
	elif(args.test_func==2):
		VSS_demo(args)
	elif(args.test_func==3):
		vrf_test(args)
	elif(args.test_func==4):
		vdf_test(args)
	else:
		rsa_test(args)
