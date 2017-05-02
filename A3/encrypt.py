import requests
import sys
import base64

last_cyper_text = bytearray([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])

def read_input_and_padding():
	plaintext = bytearray([ord(x) for x in sys.argv[1]])  # read input, and change it into byte array
	remainder = len(plaintext) % 16
	if remainder != 0:		# append the padding when neeeded
		temp = [0 for i in range(16 - remainder)]
		temp[0] = 16 - remainder
		plaintext += bytearray(temp)
	return plaintext

def break_into_blocks(plaintext):
	block_lst = []
	i = 0
	while i < len(plaintext):
		block_lst.append(plaintext[i:i +16])
		i += 16
	return block_lst

input_t = read_input_and_padding()
block_lst = break_into_blocks(input_t)
result_lst = [bytearray(16) for i in range(len(block_lst) + 1)] 


for i in range(len(block_lst) - 1, -1, -1):
	cur_p = block_lst[i]
	fake_iv = bytearray(16)  # fake iv, used to guess the middle_result value
	middle_result = bytearray(16)  # the intermidate value, we will use thit to generate the next cypertext
	for j in range(15, -1, -1): # now try from the last byte, which has index 15, unitl we guess to index 0
		response_code = 500
		while response_code != 200:  # we will keep guessing until we got the 200 response
			fake_iv[j] += 1
			cur_cookie = {'user': base64.b64encode(fake_iv + result_lst[i+1])} 
			r = requests.get('http://ugster20.student.cs.uwaterloo.ca:4555', cookies=cur_cookie)
			response_code = r.status_code
			# print response_code

		# now the response code is 200, we have the guessed the value
		# now the inter will have i to the end bytes correctly guessed
		middle_result[j] = fake_iv[j] ^ (16-j)
		fake_iv[j] = 0 ^ middle_result[j]  # update to help guess the next byte, we do XOR 0 because of the padding format k0000000...
	
	temp = bytearray(16)
	for k in range(16):
		temp[k] = cur_p[k] ^ middle_result[k]


	result_lst[i] = temp

result = bytearray()
for b in result_lst:
	result += b

print base64.b64encode(''.join([chr(r) for r in result]))




