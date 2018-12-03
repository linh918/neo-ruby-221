require 'open-uri'
require 'json'
require 'digest/sha2'
require 'bigdecimal'
require 'bitcoin'
require 'ecdsa'
require 'securerandom'
require 'base64'
require 'crypto_gost'
require 'jose'
require 'drbg-rb'

tx_sample = {
  "txid": "2570f939f56afa58b2e1a0bca2d092d6b6d2f73dce26089a768bee7fa61875fd",
  "serialized": "80000001c4a7b28d46d20a451e06997751978b06f88c0e0cd494416f95975476fe5b55220100029b7cffdaa674beae0f930ebe6085af9093e5fe56b34a5c220ccdcf6efc336fc500e1f505000000003775292229eccdf904f16fff8e83e7cffdc0f0ce9b7cffdaa674beae0f930ebe6085af9093e5fe56b34a5c220ccdcf6efc336fc5002aa1c16d00000035b20010db73bf86371075ddfba4e6596f1ff35d01414051c2e6e2993c6feb43383131ed2091f4953747d3e16ecad752cdd90203a992dea0273e98c8cd09e9bfcf2dab22ce843429cdf0fcb9ba4ac93ef1aeef40b207832321031d8e1630ce640966967bc6d95223d21f44304133003140c3b52004dc981349c9ac",
  "deserialized": {
    "type": 128,
    "version": 0,
    "attributes": [],
    "inputs": [
      {
        "prevHash": "22555bfe765497956f4194d40c0e8cf8068b97517799061e450ad2468db2a7c4",
        "prevIndex": 1
      }
    ],
    "outputs": [
      {
        "assetId": "c56f33fc6ecfcd0c225c4ab356fee59390af8560be0e930faebe74a6daff7c9b",
        "value": 1,
        "scriptHash": "cef0c0fdcfe7838eff6ff104f9cdec2922297537"
      },
      {
        "assetId": "c56f33fc6ecfcd0c225c4ab356fee59390af8560be0e930faebe74a6daff7c9b",
        "value": 4714,
        "scriptHash": "5df31f6f59e6a4fbdd75103786bf73db1000b235"
      }
    ]
  }
}
transaction = {
  type: 128,
  version: 0,
  attributes: [],
  inputs: [
    {
      prevHash: "993fe746b29363562f53d88c69854436a7f16959dbb8bc3dd744a5abf933235a",
      prevIndex: 1
    }
  ],
  outputs: [
    {
      assetId: "c56f33fc6ecfcd0c225c4ab356fee59390af8560be0e930faebe74a6daff7c9b",
      value: 40,
      scriptHash: "5277ca8a7f4bdde842d036aae3c0b2154c077274"
    },
     {
      assetId: "c56f33fc6ecfcd0c225c4ab356fee59390af8560be0e930faebe74a6daff7c9b",
      value: 99999920,
      scriptHash: "e9eed8dc39332032dc22e5d6e86332c50327ba23"
    }
  ],
  # scripts: [
  #   {
  #     invocationScript: '40a30683a9483614659ab82c8e2698c408c4015e9272ca0e311f1b75bc9ce32f30ebb4c17c484f8c76726b20671bd695f3dfa6756af9a0929d1f0cf234531e09ef',
  #     verificationScript: '21031d8e1630ce640966967bc6d95223d21f44304133003140c3b52004dc981349c9ac'
  #   }
  # ]
}

def get_verification_script_from_public_key public_key
  return "21" + public_key + "ac"
end

def sha256 hex 
  Digest::SHA256.hexdigest([hex].pack("H*"))
end

def input_serialize(input)
  return (reverse_hex(input[:prevHash]) + reverse_hex(num_2_hex(input[:prevIndex], 2)))
end

def output_serialize(output)
  return reverse_hex(output[:assetId]) + reverse_hex(hex_from_value(output[:value])) + reverse_hex(output[:scriptHash])
end


def num_2_hex(num, size =1, little_endian = false)
  if little_endian
    num.to_s(16).rjust(size * 2,"0").scan(/(..)/).reverse.join()
  else
    num.to_s(16).rjust(size * 2,"0").scan(/(..)/).join()
  end
end

def serialize_array_input props
  num_2_var_int(props.length) + props.map{ |e|  input_serialize(e) }.join('')
end 

def serialize_array_output props
  num_2_var_int(props.length) + props.map{ |e|  output_serialize(e)}.join('')
end  

def reverse_hex(hex)
  return hex.scan(/../).reverse.join('')
end

def num_2_var_int(num) 
  if num < 0xfd
    return num_2_hex(num)
  elsif num <= 0xffff
    return "fd" + num_2_hex(num, 2)
  elsif num <= 0xffffffff
    return "fe" + num_2_hex(num, 2)
  else num <= 0xffff
    return "ff" + num_2_hex(num, 2)
  end  
end

def hex_from_value(value)
  big = BigDecimal.new(value * 100_000_000)
  hex_string = big.to_i.to_s(16)
  "0"*(16 - hex_string.length) + hex_string
end

def input_serialize(input)
  return (reverse_hex(input[:prevHash]) + reverse_hex(num_2_hex(input[:prevIndex], 2)))
end

def from_signature (sig, public_key)
  invocation_script = "40" + sig
  verification_script = get_verification_script_from_public_key(public_key)
  return {
    invocationScript: invocation_script,
    verificationScript: get_verification_script_from_public_key(public_key)
  }
end

def witness_serialized (witness)
  invo_length = num_2_var_int(witness[:invocationScript].length/2)
  veri_length = num_2_var_int(witness[:verificationScript].length/2)
  return (invo_length + witness[:invocationScript] + veri_length + witness[:verificationScript])     
end

def serialized_array_witnesses(props)
  num_2_var_int(props.length) + props.map{ |e|  witness_serialized(e) }.join('')      
end    

def serialized_tx (sign = false, transaction)
  tx = ""
  tx << num_2_hex(transaction[:type])
  tx << num_2_hex(transaction[:version])
  tx << ""
  tx << "00"
  tx << serialize_array_input(transaction[:inputs])
  tx << serialize_array_output(transaction[:outputs])
  if(sign)
    tx << serialized_array_witnesses(transaction[:scripts])
  end  
  return tx
end  

def sign(hex, private_key)
  group = ECDSA::Group::Secp256r1
  signature = nil
  while signature.nil?
    temp_key = 1 + SecureRandom.random_number(group.byte_length - 1)
    signature = ECDSA.sign(group, private_key.to_i(16), hex, temp_key)
  end
  return signature.r.to_s(16) + signature.s.to_s(16)
end

  #*************************************************************************************
  # puts num_2_hex(128)
  # puts num_2_hex(44, 2, true)
  # puts reverse_hex("abcdef")
  # puts input_serialize(input)
  # puts serialized_tx(false, transaction)
  # puts sha256(hex)

  private_key = "1dd37fba80fec4e6a6f13fd708d8dcb3b29def768017052f6c930fa1c5d90bbb"
  public_key = "031a6c6fbbdf02ca351745fa86b9ba5a9452d785ac4f7fc2b7548ca2a46c4fcf4a"
  
  # 6188572312889309552908601640552898960147655325368818291819266549176485034125532314956929281328670260408023461742098137538981688222050461901739095977411776
  # "de87e10e13e1dd1da7798f94d4873670bc9f0058d021e9f9aa2bc80dd8a08280ec0930beee841b8cff66378f22c1e977652184e39090bd696784f1fa209c84c9"
  
  # hex =  serialized_tx(transaction)
  #  puts "sign -------"
  # signature = sign(hex, private_key)
  # puts "sig:"+ signature
  # scripts = [from_signature(signature,public_key)]
  # puts scripts.class
  # transaction[:scripts] = scripts
  # puts "tx:", transaction
  # tx_serialized = serialized_tx(true, transaction)
  # puts tx_serialized
    key1 = OpenSSL::PKey::EC.new("prime256v1").generate_key

    key2 = OpenSSL::PKey::EC.new
    key2.group = key1.group
    key2.private_key = key1.private_key
    key2.public_key = key1.public_key

    puts key2.private_key
    data1 = "sdsd"
    sig = key2.dsa_sign_asn1(data1)
    puts sig.to_i.to_s(16)
