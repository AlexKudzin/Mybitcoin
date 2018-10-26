#p2pkh
# Thanks for the amazing tutorials could you please do an updated on for python3? or add a lot of comments to this? 
# PLEASE ANOTATE ALL ??
# PLEASE CORRECT ANOTATIONS


#MODULES TO IMPORT
import hashlib
import ecdsa

#THIS SECTION CREATES A TRANSACTION
#Defines the raw transaction, fee is based on the size of the transaction + signature (100mb)
#Therefore do a raw transaction with a blank signature?? to get fee??
class raw_tx:
        version         = (1).to_bytes(4, byteorder="little", signed=False)                     #version 1, covert (1) to bytes (4 bytes long, littlendian, unsigned) 
        tx_in_count     = (1).to_bytes(1, byteorder="little", signed=False)                     #?? what is 1?? convert something to bytes (1 bytes long, littlendian, unsigned) 
        tx_in           = "soon!"#TEMP    #main input, previous transaction bob recieving from alice                                           #place holder?
        #tx_in_n        = "soon!"#TEMP    #any other inputs                                     #place holder?
        tx_out_count    = (1).to_bytes(1, byteorder="little", signed=False)                     #?? what is 1?? convert something to bytes (1 bytes long, littlendian, unsigned) 
        tx_out_1        = "soon!"#TEMP    #Paying  XYZ                                          #place holder?
        tx_out_2        = "soon!"#TEMP    #change  ABC                                          #place holder?
        #tx_out_n       = "soon!"#TEMP    #any other payees                                     #place holder?
        lock_time       = (101).to_bytes(4, byteorder="little", signed=False)                   #in 101 blocks or in ~16:50:00 if block time ~00:10:00 #numbers more then 500million are in seconds from 00:00:00 1 January 1970, currently 1,540,543,517 
        tx_out_value    = (299000000).to_bytes(8, byteorder="little", signed=True)              #?? what is 299000000, the value being sent?? convert satoshis? to bytes (8 bytes long, littlendian, signed) 
 
#?? WHAT IS THIS?? output script of the pervious transaction?
#                               Address	15WT9oQn1guhp5TMG9tzngdEYEmeDtn3HN
#                               Hash 160	31726579c6ab17fe2f85e236309d4c0bcff28055
#                               Addr to H160    Alice_hashed_pub_key = base58.b58encode_check(Alice_addr)[1:].hex() 
# Hash 160 is a 20 bytes hash of the public key (ripemd160 hash of the sha256 hash of the public key) its equal to public address
#       OP_DUP OP_HASH160       (len)           31726579c6ab17fe2f85e236309d4c0bcff28055        OP_EQUALVERIFY  OP_CHECKSIG        
#       "76      a9             14              Alice_hashed_pub_key                            88              ac
#                                       76a914  31726579c6ab17fe2f85e236309d4c0bcff28055        88ac
tx_out_pubScript = bytes.fromhex("      76a914  31726579c6ab17fe2f85e236309d4c0bcff28055        88ac")    
# =                             b'v\xa9\x141rey\xc6\xab\x17\xfe/\x85\xe260\x9dL\x0b\xcf\xf2\x80U\x88\xac'

#?? set size of "tx_out_pubScript_size" to 19 bytes?? tx_out_pubScript is a 50 char hex =  
tx_out_pubScript_size = bytes.fromhex("19")
# = b'\x19'


#?? THIS IS THE PREVIOUS TRANSACTION ID FROM THE BLOCK CHAIN - INSERT HERE THE TX ADDR WHICH GAVE YOU TEST NET COINS
#       DO THIS FOR EACH INPUT
#https://www.blockchain.com/btc/tx/     3df07acef5b210d34c9dfe69708cc26d0f8e11a63ee1886973b30f4ff196fcd6
prv_tx_id = bytes.fromhex("             192730e77f297a5b805fac2a833948c761e79c1d74929d170523d624d20aff193") #?? #(multi_sig_script_address)      #hash of the previous transaction  
#previous transaction id?


#little-endian to big-endian
reversed_prv_tx_id = bytearray(prv_tx_id)                                                       #all info is in little-endian, however, it needs to be big-endian
reversed_prv_tx_id.reverse()                                                                    #the little-endian to big-endian function

#??
index = (2).to_bytes(4, byteorder="little", signed=False)                                       #??


#?? WHAT IS THIS?? Signing script of this transaction?? 
#                               Address	1DFBWY4USbN7dmHKkd5osY7VipcucmRw6Q
#                               Hash 160	86501b046d9c67aa1e361cbf49cfc6482fd16d1b
#                               Addr to H160    Bob_hashed_pub_key = base58.b58encode_check(Bob_addr)[1:].hex()
# Hash 160 is a 20 bytes hash of the public key (ripemd160 hash of the sha256 hash of the public key) its equal to public address
#       OP_DUP OP_HASH160       (len)           31726579c6ab17fe2f85e236309d4c0bcff28055        OP_EQUALVERIFY  OP_CHECKSIG        
#       "76      a9             14              Bob_hashed_pub_key ???                          88              ac
#                                       76a914  86501b046d9c67aa1e361cbf49cfc6482fd16d1b        88ac
sigScript_raw = bytes.fromhex("         76a914  86501b046d9c67aa1e361cbf49cfc6482fd16d1b        88ac")             #?? why that hash?

#?? set size of "sigScript_raw_size" to 19 bytes??
sigScript_raw_size = bytes.fromhex("19")                                                        #??

#??
#One sequence number per input
#locktime is ignored if any of the sequence numbers are ffffffff.
#                                 caps for clarity input as lower case.
#change sequence to             ("FFFFFFFD") for replace by fee.
#change sequence to             ("FFFFFFFF") for time lockdisabled, vanilla/defalt.
#change sequence to             ("FFFFFFFE") for time lock.
sequence = bytes.fromhex        ("fffffffe")                                                            #??

#WHY RAW? is this to get a fee estimate??
#combine all the information into one string
raw_tx =    (   version
            +   tx_in_count
            +   reversed_prv_tx_id
            +   index
            +   sigScript_raw_size
            +   sigScript_raw
            +   sequence
            +   tx_out_count
            +   tx_out_value
            +   tx_out_pubScript_size
            +   tx_out_pubScript
            +   lock_time
            +   (1).to_bytes(4, byteorder="little", signed=False))  

#print the string to check it
print(raw_tx.hex())

#first hasing # why isnt it in this format? { hashlib.sha256(hashlib.sha256(raw_tx).digest()).digest() }
hash_1 = hashlib.sha256(raw_tx).digest()
#second hasing
hash_2 = hashlib.sha256(hash_1).digest()

#print the has to check it
print(hash_2.hex())


#IMPORT PRIVATE KEY FROM PREVIOUS TUTORIAL INSTEAD
#TOP LINE IS THIS TUTORIAL
#BOTTOM LINE IS PREVIOUS TUTORIAL Keys_python3Plus

#SKIP AS SAME
#private_key = bytes.fromhex("")    #THIS TUTORIAL
#private_key = os.urandom(32)       #Keys_python3Plus TUTORIAL

#SKIP AS SAME
#signing_key = ecdsa.SigningKey.from_string(private_key, curve = ecdsa.SECP256k1)   #THIS TUTORIAL
#signing_key = ecdsa.SigningKey.from_string(private_key, curve = ecdsa.SECP256k1)   #Keys_python3Plus TUTORIAL 

#QUERY AS NOT SAME
verifying_key = signing_key.get_verifying_key() #what does the get_verifying_key() do different to verifying_key?
#verifying_key = signing_key.verifying_key      #Keys_python3Plus TUTORIAL 

#SKIP AS SAME
#public_key = bytes.fromhex("04") + verifying_key.to_string()           #THIS TUTORIAL
#public_key = bytes.fromhex("04") + verifying_key.to_string()           #Keys_python3Plus TUTORIAL

#NEW CODE                       #hash_2 = second hashing of raw_tx through sha256
signature = signing_key.sign_digest(hash_2, sigencode = ecdsa.util.sigencode_der_canonize) 
#generates a "signature" takes the SECP256k1 points of the private key 

#NEW CODE
sigScript = ((len(signature) + 1).to_bytes(1, byteorder="little", signed=False)
            + signature
            + bytes.fromhex("01")
            +(len(public_key)).to_bytes(1, byteorder="little", signed=False)
            + public_key)

#NEW CODE
sigScript_size = (int(len(sigScript))).to_bytes(1, byteorder="little", signed=False)

#combine all & signature into one transaction
REAL_TX =   (   version
            +   tx_in_count
            +   reversed_prv_tx_id
            +   index
            +   sigScript_size
            +   sigScript
            +   sequence
            +   tx_out_count
            +   tx_out_value
            +   tx_out_pubScript_size
            +   tx_out_pubScript
            +   lock_time)

#check the transaction            
print(REAL_TX.hex())

#Why this hash? #why not this format? { hashlib.sha256(hashlib.sha256(REAL_TX).digest()).digest() }
# what is the long hex code here??
hash_1 = hashlib.sha256(bytes.fromhex("0100000001e18e68f7fc653a9f3e249c887f03963bf5c8d10f8afc01944a1126af36e98a19060000008a4730440220113f91f8d10725b3a279cf4bd4de3d43c21d94210d22acde8f9e58c7240e884c022061b05a6ccdf8dbad5b34eb57ff6832eb2a7cb584b828bdd8ada6ec843438348d01410448d297e22dbd448f2a00501a6336c15b809df00228c527e4221338d0ce9999439e80f93a6b4c1e8281724967a62bcf44142d46dfc72d31f58b8304556f5f70aaffffffff01c060d211000000001976a91486501b046d9c67aa1e361cbf49cfc6482fd16d1b88ac00000000")).digest()
hash_2 = hashlib.sha256(hash_1).digest()

#print result
print(hash_2.hex())

