require 'open-uri'
require 'json'
require 'digest/sha2'
require 'bigdecimal'
require 'bitcoin'

def little_endian_hex_of_n_bytes(i, n)
  i.to_s(16).rjust(n * 2,"0").scan(/(..)/).reverse.join()
end

@private_key = "5JLJAmCk7TboretVcXT8diEEvNYmRomAUhgxdJGwWs6eAusJzLW" # Wallet import format (starts with a 5)
w2 = Bitcoin.decode_base58(@private_key)
puts w2
w3 = w2[0..-9]
puts w3
@secret = w3[2..-1]
puts @secret
a = "7d128a6d096f0c14c3a25a2b0c41cf79661bfcb4a8cc95aaaea28bde4d732344"
sha ="99a29005e7a3bb4db34a08ce02bf2ac6381c5019b8fe52e5e8cdb09dd8eca002"
@keypair = Bitcoin.open_key(a)
puts @keypair
signature_binary = @keypair.dsa_sign_asn1([sha].pack("H*"))
puts "---:" + signature_binary
signature = signature_binary.unpack("H*").first
puts signature
hash_code_type = "01"

# signature_plus_hash_code_type_length = little_endian_hex_of_n_bytes((signature + hash_code_type).length / 2, 1)
# puts signature_plus_hash_code_type_length