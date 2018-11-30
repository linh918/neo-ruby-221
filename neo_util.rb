require 'open-uri'
require 'json'
require 'digest/sha2'
require 'bigdecimal'
require 'bitcoin'
require 'ecdsa'
require 'securerandom'
require 'base64'
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
          prevHash: "22555bfe765497956f4194d40c0e8cf8068b97517799061e450ad2468db2a7c4",
          prevIndex: 1
        }
      ],
      outputs: [
        {
          assetId: "c56f33fc6ecfcd0c225c4ab356fee59390af8560be0e930faebe74a6daff7c9b",
          value: 1,
          scriptHash: "cef0c0fdcfe7838eff6ff104f9cdec2922297537"
        },
        {
          assetId: "c56f33fc6ecfcd0c225c4ab356fee59390af8560be0e930faebe74a6daff7c9b",
          value: 4714,
          scriptHash: "5df31f6f59e6a4fbdd75103786bf73db1000b235"
        }
      ]
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

  def output_serialize(outut)
    return reverse_hex(outut[:assetId]) + outut[:value].to_s(16) + reverse_hex(outut[:scriptHash])
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
    num_2_var_int(props.length) + props.map{ |e|  output_serialize(e) }.join('')
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

  def input_serialize(input)
    return (reverse_hex(input[:prevHash]) + reverse_hex(num_2_hex(input[:prevIndex], 2)))
  end

  def serialized_tx (sign = false, transaction)
    tx = ""
    tx << num_2_hex(transaction[:type])
    tx << num_2_hex(transaction[:version])
    tx << ""
    tx << serialize_array_input(transaction[:inputs])
    tx << serialize_array_output(transaction[:outputs])
    # if(sign)
    # tx << serialize_array(transaction[:scripts])
    # end  
  end  

    puts num_2_hex(128)
  
    puts num_2_hex(44, 2, true)
    puts reverse_hex("abcdef")
    input = {
      prevHash:
        "22555bfe765497956f4194d40c0e8cf8068b97517799061e450ad2468db2a7c4",
      prevIndex: 1
    }
    hex = "80000001ab0000029b7cffdaa674beae0f930ebe6085af9093e5fe56b34a5c220ccdcf6efc336fc500e1f5050000000035b20010db73bf86371075ddfba4e6596f1ff35d9b7cffdaa674beae0f930ebe6085af9093e5fe56b34a5c220ccdcf6efc336fc500e9a435000000003775292229eccdf904f16fff8e83e7cffdc0f0ce"
    puts input_serialize(input)
    puts serialized_tx(false, transaction)

    puts sha256(hex)
    private_key = "0x7d128a6d096f0c14c3a25a2b0c41cf79661bfcb4a8cc95aaaea28bde4d732344"

    a = "0x7d128a6d096f0c14c3a25a2b0c41cf79661bfcb4a8cc95aaaea28bde4d732344"
    key = Bitcoin.open_key(a)
  digest = Digest::SHA2.digest("message")
  group = ECDSA::Group::Secp256k1
  private_key_2 = 1 + SecureRandom.random_number(group.order - 1)
  puts private_key_2.class
  puts 'private key: %#x' % private_key
  signature = nil
  while signature.nil?
    temp_key = 1 + SecureRandom.random_number(group.order - 1)
    signature = ECDSA.sign(group, private_key.to_i(16), sha256(hex), temp_key)
  end

  puts 'signature: '
  puts '  r: %#x' % signature.r
  puts '  s: %#x' % signature.s


  