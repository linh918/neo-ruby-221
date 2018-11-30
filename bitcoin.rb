require 'open-uri'
require 'json'
require 'digest/sha2'
require 'bigdecimal'
require 'bitcoin'

SATOSHI_PER_BITCOIN = BigDecimal.new("100000000")


####################
###### SETUP #######
####################

@to_address = "1JJynffTaq3bWcWTXnC4P68VMeNNHdVmMy"

@from_address = "1HnhWpkMHMjgt167kvgcPyurMmsCQ2WPgg"
@private_key = "5JLJAmCk7TboretVcXT8diEEvNYmRomAUhgxdJGwWs6eAusJzLW" # Wallet import format (starts with a 5)

@amount = BigDecimal.new("0.000")
@transaction_fee = @amount >=  BigDecimal.new("0.01") ?  BigDecimal.new("0") :  BigDecimal.new("0.0001")

puts "About to send #{@amount.to_f} bitcoins from #{@from_address[0..5]}... to #{@to_address[0..5]}... " + (@transaction_fee > 0 ? "plus a #{@transaction_fee.to_f} transaction fee." : "")

####################
##### BALANCE ######
####################

puts "Fetching balance for #{@from_address[1..5]} from Chain..."
url = "https://api.chain.com/v1/bitcoin/addresses/#{@from_address}?key=GUEST-TOKEN"

response = JSON.parse(open(url).read)
@balance = BigDecimal.new(response["balance"]) / SATOSHI_PER_BITCOIN

puts "Current balance of sender: #{@balance.to_f} BTC"

raise "Insuffient funds" if @balance < @amount + @transaction_fee

####################
###### INPUTS ######
####################

url = "https://api.chain.com/v1/bitcoin/addresses/#{@from_address}/unspents?key=GUEST-TOKEN"

@unspent_outputs = JSON.parse(open(url).read)
@inputs = []

input_total = BigDecimal.new("0")
@unspent_outputs.each do |output|
  p output["transaction_hash"].to_s
    @inputs <<  {
      previousTx: output["transaction_hash"],
      index: output["output_index"],
      scriptSig: nil # Sign it later
    }
    amount = BigDecimal.new(output["value"]) / SATOSHI_PER_BITCOIN
    puts "Using #{amount.to_f} from output #{output["output_index"]} of transaction #{output["transaction_hash"][0..5]}..."
    input_total += amount
    break if input_total >= @amount + @transaction_fee
end

@change = input_total - @transaction_fee - @amount

puts "Spend #{@amount.to_f} and return #{@change.to_f} as change."

raise "Unable to process inputs for transaction" if input_total < @amount + @transaction_fee || @change < 0

####################
##### OUTPUTS ######
####################

message = "Chainengage"
message_hex = "%02X" % (message.each_byte.size)
message_hex += message.each_byte.map { |b| "%02X" % b }.join

# Lean on bitcoin-ruby for clean decoding
from_address_hex = Bitcoin.decode_base58(@from_address)
to_address_hex = Bitcoin.decode_base58(@to_address)

p message.bytesize
p [message.bytesize].pack("C").to_s
p [message.bytesize].pack("C").unpack("H*")[0].to_s

@outputs = [
  { # Amount to transfer (leave out the leading zeros and 4 byte checksum)
      value: @amount,
      scriptPubKey: "OP_RETURN " + message_hex
      #scriptPubKey: "OP_RETURN " + [message.bytesize].pack("C").unpack("H*")[0]
      #scriptPubKey: "OP_DUP OP_HASH160 " + (to_address_hex[2..-9].size / 2).to_s(16) + " " + to_address_hex[2..-9] + " OP_EQUALVERIFY OP_CHECKSIG "
      # OP_DUP is the default payment script: https://en.bitcoin.it/wiki/Script
    }
]

if @change > 0
  @outputs << {
    value: @change,
    scriptPubKey: "OP_DUP OP_HASH160 " + (from_address_hex[2..-9].size / 2).to_s(16) + " " + from_address_hex[2..-9] + " OP_EQUALVERIFY OP_CHECKSIG "
  }
  # Any property not specified in an output goes to the miners (transaction fee)
end

####################
#### SIGNATURE #####
####################

# Check that the prior transaction pubKey matches the private key (valid signature)
w2 = Bitcoin.decode_base58(@private_key)
w3 = w2[0..-9]
@secret = w3[2..-1]

@keypair = Bitcoin.open_key(@secret)
raise "Invalid keypair" unless @keypair.check_key

step_2 = (Digest::SHA2.new << [@keypair.public_key_hex].pack("H*")).to_s  # (Digest::SHA2.new << [pubKey].pack("H*")).to_s -> bb905b336...
step_3 = (Digest::RMD160.new << [step_2].pack("H*")).to_s                 # (Digest::RMD160.new << [step_2].pack("H*")).to_s -> 23376070c...
step_4 = "00" + step_3                                                    # "00" + step_3
step_5 = (Digest::SHA2.new << [step_4].pack("H*")).to_s                   # (Digest::SHA2.new << [step_4].pack("H*")).to_s
step_6 = (Digest::SHA2.new << [step_5].pack("H*")).to_s                   # (Digest::SHA2.new << [step_5].pack("H*")).to_s
step_7 = step_7 = step_6[0..7]                                            # step_7 = step_6[0..7] ->  b18a9aba
step_8 = step_4 + step_7                                                  # step_4 + step_7 ->  00233760...b18a9aba
step_9 = Bitcoin.encode_base58(step_8)                                    # Bitcoin.encode_base58(step_8)  -> 14DCzMe... which is the bitcoin address

raise "Public key does not match private key" if @from_address != step_9

puts "Public key matches private key, so we can sign the transaction..."

# Temporary value for signing purposes. Normally you
# should obtain the actual scriptSig from each of the outputs,
# but Blockchain (json) doesn't give us that. We're just guessing
# that it's the default. This is why this script won't
# work for non-standard transactions.
# The scriptsig uses the address in hex, but without the leading 00 and 4
# byte checksum at the end.

scriptSig = "OP_DUP OP_HASH160 " + (from_address_hex[2..-9].size / 2).to_s(16) + " " + from_address_hex[2..-9] + " OP_EQUALVERIFY OP_CHECKSIG "

@inputs.collect!{|input|
  {
    previousTx: input[:previousTx],
    index: input[:index],
    # Add 1 byte for each script opcode:
    scriptLength: from_address_hex[2..-9].length / 2 + 5,
    scriptSig: scriptSig,

    sequence_no: "ffffffff" # Ignored
  }
}

@transaction = {
  version: 1,
  in_counter: @inputs.count,
  inputs: @inputs,
  out_counter: @outputs.count,
  outputs: @outputs,
  lock_time: 0,
  hash_code_type: "01000000" # Temporary value used during the signing process
}

# Serialize and create the input signatures. Then add these signatures back into the transaction and serialize it again.

puts "Readable version of the transaction (numbers in strings are hex, otherwise decimal)\n\n"
p @transaction

def little_endian_hex_of_n_bytes(i, n)
  i.to_s(16).rjust(n * 2,"0").scan(/(..)/).reverse.join()
end

def parse_script(script)
  script.gsub("OP_DUP", "76").gsub("OP_HASH160", "a9").gsub("OP_EQUALVERIFY", "88").gsub("OP_CHECKSIG", "ac").gsub("OP_RETURN", "6a")
end

def serialize_transaction(transaction)
  tx = ""
  # Little endian 4 byte version number: 1 -> 01 00 00 00
  tx << little_endian_hex_of_n_bytes(transaction[:version],4) + "\n"
  # You can also use: transaction[:version].pack("V")

  # Number of inputs
  tx << little_endian_hex_of_n_bytes(transaction[:in_counter],1) + "\n"

  transaction[:inputs].each do |input|
    tx << little_endian_hex_of_n_bytes(input[:previousTx].hex, input[:previousTx].length / 2) + " "
    tx << little_endian_hex_of_n_bytes(input[:index],4) + "\n"
    tx << little_endian_hex_of_n_bytes(input[:scriptLength],1) + "\n"
    tx << parse_script(input[:scriptSig]) + " "
    tx << input[:sequence_no] + "\n"
  end

  # Number of outputs
  tx << little_endian_hex_of_n_bytes(transaction[:out_counter],1) + "\n"

  transaction[:outputs].each do |output|
    tx << little_endian_hex_of_n_bytes((output[:value] * SATOSHI_PER_BITCOIN).to_i,8) + "\n"
    unparsed_script = output[:scriptPubKey]
    puts "UNPARSED: ------------------------------"
    puts unparsed_script
    tx << little_endian_hex_of_n_bytes(parse_script(unparsed_script).gsub(" ", "").length / 2, 1) + "\n"
    puts little_endian_hex_of_n_bytes(parse_script(unparsed_script).gsub(" ", "").length / 2, 1) + "\n"
    tx << parse_script(unparsed_script) + "\n"
    puts parse_script(unparsed_script) + "\n"
  end

  tx << little_endian_hex_of_n_bytes(transaction[:lock_time],4) + "\n"
  tx << transaction[:hash_code_type] # This is empty after signing
  tx
end

@utx = serialize_transaction(@transaction)

puts "\nHex unsigned transaction:"
puts @utx

# Remove line breaks and spaces
@utx.gsub!("\n", "")
@utx.gsub!(" ", "")

# Twice Sha256 and sign

sha_first = (Digest::SHA2.new << [@utx].pack("H*")).to_s
sha_second = (Digest::SHA2.new << [sha_first].pack("H*")).to_s

puts "\nHash that we're going to sign: #{sha_second}"

signature_binary = @keypair.dsa_sign_asn1([sha_second].pack("H*"))

signature = signature_binary.unpack("H*").first

hash_code_type = "01"
signature_plus_hash_code_type_length = little_endian_hex_of_n_bytes((signature + hash_code_type).length / 2, 1)
pub_key_length = little_endian_hex_of_n_bytes(@keypair.public_key_hex.length / 2, 1)

scriptSig = signature_plus_hash_code_type_length + " " + signature + " "  + hash_code_type + " "  + pub_key_length + " " + @keypair.public_key_hex

# Replace scriptSig and scriptLength for each of the inputs:
@transaction[:inputs].collect!{|input|
  {
    previousTx:   input[:previousTx],
    index:        input[:index],
    scriptLength: scriptSig.gsub(" ","").length / 2,
    scriptSig:    scriptSig,
    sequence_no:  input[:sequence_no]
  }
}

@transaction[:hash_code_type] = ""

@tx = serialize_transaction(@transaction)

# Take out all line breaks and spaces
@tx.gsub!("\n", "")
@tx.gsub!(" ", "")

puts "\nSigned transaction hex: (#{ @tx.size / 2 } bytes)\n\n"
puts @tx