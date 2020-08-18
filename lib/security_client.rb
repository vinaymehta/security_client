require "security_client/version"
require 'ostruct'
require 'httparty'
require "active_support/all"
require 'webrick'

module SecurityClient
  class Voltron

    def initialize access_key_id:, secret_signing_key:, secret_crypto_access_key: , host:
      @access_key_id = access_key_id
      @secret_signing_key = secret_signing_key
      @secret_crypto_access_key = secret_crypto_access_key
      @host = host
    end

    def get_attributes
      return OpenStruct.new(access_key_id: @access_key_id, secret_signing_key: @secret_signing_key, secret_crypto_access_key: @secret_crypto_access_key, host: @host)
    end

    def encrypt uses:, data:
      creds = self.get_attributes
      begin
        enc = SecurityClient::Encryption.new(creds, 1)
        res = enc.begin() + enc.update(data) + enc.end()
        enc.close()
      rescue
        enc.close() if enc
        raise
      end
      puts res
      return res
    end

    def decrypt data:
      creds = self.get_attributes
      begin
        dec = Decryption.new(creds)
        res = dec.begin() + dec.update(data) + dec.end()
        dec.close()
      rescue
        dec.close() if dec
        raise
      end
      puts res
      return res
    end

  end
end

class SecurityClient::Encryption
  def initialize(creds, uses)

    raise RuntimeError, 'Some of your credentials are missing, please check!' if !validate_creds(creds)

    # Set host, either the default or the one given by caller
    @host = creds.host.blank? ? VOLTRON_HOST : creds.host

    # Set the credentials in instance varibales to be used among methods
    # The client's public API key (used to identify the client to the server
    @papi = creds.access_key_id

    # The client's secret API key (used to authenticate HTTP requests)
    @sapi = creds.secret_signing_key

    # The client's secret RSA encryption key/password (used to decrypt the client's RSA key from the server). This key is not retained by this object.
    @srsa = creds.secret_crypto_access_key

    # Build the endpoint URL
    url = endpoint_base + '/encryption/key'

    # Build the Request Body with the number of uses of key
    query = {uses: uses}

    # Retrieve the necessary headers to make the request using Auth Object
    headers = SecurityClient::Auth.build_headers(@papi, @sapi, endpoint, query, @host,'post')

    @encryption_started = false
    @encryption_ready = true

    # Request a new encryption key from the server. if the request
    # fails, the function raises a HTTPError indicating
    # the status code returned by the server. this exception is
    # propagated back to the caller

    begin
      response = HTTParty.post(
        url,
        body: query.to_json,
        headers: headers
      )
    rescue HTTParty::Error
      raise RuntimeError, 'Cant reach server'
    end

    # Response status is 201 Created
    if response.code == WEBrick::HTTPStatus::RC_CREATED
      # The code below largely assumes that the server returns
      # a json object that contains the members and is formatted
      # according to the Voltron REST specification.

      # Build the key object
      @key = {}
      @key['id'] = response['key_fingerprint']
      @key['session'] = response['encryption_session']
      @key['security_model'] = response['security_model']
      @key['algorithm'] = response['security_model']['algorithm'].downcase
      @key['max_uses'] = response['max_uses']
      @key['uses'] = 0
      @key['encrypted'] = Base64.strict_decode64(response['encrypted_data_key'])

      # Get encrypted private key from response body
      encrypted_private_key = response['encrypted_private_key']
      # Get wrapped data key from response body
      wrapped_data_key = response['wrapped_data_key']
      # Decrypt the encryped private key using @srsa supplied
      private_key = OpenSSL::PKey::RSA.new(encrypted_private_key,@srsa)
      # Decode WDK from base64 format
      wdk = Base64.strict_decode64(wrapped_data_key)
      # Use private key to decrypt the wrapped data key
      dk = private_key.private_decrypt(wdk,OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
      @key['raw'] = dk
      # Build the algorithm object
      @algo = SecurityClient::Algo.new.get_algo(@key['algorithm'])
    else
      # Raise the error if response is not 201
      raise RuntimeError, "HTTPError Response: Expected 201, got #{response.code}"
    end

  end

  def begin
    # Begin the encryption process

    # When this function is called, the encryption object increments
    # the number of uses of the key and creates a new internal context
    # to be used to encrypt the data.
    # If the encryption object is not yet ready to be used, throw an error
    raise RuntimeError, 'Encryption not ready' if !@encryption_ready

    # if Encryption cipher context already exists
    raise RuntimeError, 'Encryption already in progress' if @encryption_started
    # If max uses > uses
    raise RuntimeError, 'Maximum key uses exceeded' if @key['uses'] >= @key['max_uses']
    @key['uses'] += 1
    # create a new Encryption context and initialization vector
    @enc , @iv = SecurityClient::Algo.new.encryptor(@algo, @key['raw'])

    # Pack the result into bytes to get a byte string
    struct = [0, 0, @algo[:id], @iv.length, @key['encrypted'].length].pack('CCCCn')
    @encryption_started = true
    return struct + @iv + @key['encrypted']
  end

  def update(data)
    raise RuntimeError, 'Encryption is not Started' if !@encryption_started
    # Encryption of some plain text is perfomed here
    # Any cipher text produced by the operation is returned
    @enc.update(data)
  end

  def end
    raise RuntimeError, 'Encryption is not Started' if !@encryption_started
    # This function finalizes the encryption (producing the final
    # cipher text for the encryption, if necessary) and adds any
    # authentication information (if required by the algorithm).
    # Any data produced is returned by the function.

    # Finalize an encryption
    res = @enc.final
    if @algo[:tag_length] != 0
      # Add the tag to the cipher text
      res+= @enc.auth_tag
    end
    @encryption_started = false
    # Return the encrypted result
    return res
  end

  def close
    raise RuntimeError, 'Encryption currently running' if @encryption_started
    # If the key was used less times than was requested, send an update to the server
    if @key['uses'] < @key['max_uses']
      query_url = "#{endpoint}/#{@key['id']}/#{@key['session']}"
        url = "#{endpoint_base}/encryption/key/#{@key['id']}/#{@key['session']}"
        query = {actual: @key['uses'], requested: @key['max_uses']}
        headers = Auth.build_headers(@papi, @sapi, query_url, query, @host, 'patch')
        response = HTTParty.patch(
          url,
          body: query.to_json,
          headers: headers
        )
        remove_instance_variable(:@key)
      @encryption_ready = false;
    end
  end

  def endpoint_base
    @host + '/api/v0'
  end

  def endpoint
    '/api/v0/encryption/key'
  end

  def validate_creds(credentials)
    # This method checks for the presence of the credentials
    !credentials.access_key_id.blank? and !credentials.secret_signing_key.blank? and !credentials.secret_crypto_access_key.blank?
  end
end

class SecurityClient::Algo
  def set_algo
    @algorithm = {
      "aes-256-gcm"=>{
        id:0,
        algorithm: OpenSSL::Cipher::AES256,
        mode: OpenSSL::Cipher::AES256.new(:GCM),
        key_length: 32,
        iv_length: 12,
        tag_length: 16
      },
    }
  end

  def get_algo(name)
    set_algo[name]
  end

  def encryptor(obj,key, iv=nil)
    # key : A byte string containing the key to be used with this encryption
    # If the caller specifies the initialization vector, it must be
    # the correct length and, if so, will be used. If it is not
    # specified, the function will generate a new one

    cipher = obj[:mode]
    raise RuntimeError, 'Invalid key length' if key.length != obj[:key_length]

    raise RuntimeError, 'Invalid initialization vector length' if (iv!= nil and iv.length != obj[:iv_length])
    cipher.encrypt
    cipher.key = key
    iv = cipher.random_iv
    return cipher, iv
  end

  def decryptor(obj, key, iv)
    cipher = obj[:mode]
    raise RuntimeError, 'Invalid key length' if key.length != obj[:key_length]

    raise RuntimeError, 'Invalid initialization vector length' if (iv!= nil and iv.length != obj[:iv_length])
    cipher = obj[:mode]
    cipher.decrypt
    cipher.key = key
    cipher.iv = iv
    return cipher
  end
end

class SecurityClient::Auth
  def self.build_headers(papi, sapi, endpoint, query, host, http_method)

    # This function calculates the signature for the message, adding the Signature header
    # to contain the data. Certain HTTP headers are required for
    # signature calculation and will be added by this code as
    # necessary. The constructed headers object is returned

    # the '(request-target)' is part of the signed data.
    # it's value is 'http_method path?query'
    reqt = "#{http_method} #{endpoint}"

    # The time at which the signature was created expressed as the unix epoch
    created = Time.now.to_i

    # the Digest header is always included/overridden by
    # this code. it is a hash of the body of the http message
    # and is always present even if the body is empty
    hash_sha512 = OpenSSL::Digest::SHA512.new
    hash_sha512 << JSON.dump(query)
    digest = 'SHA-512='+Base64.strict_encode64(hash_sha512.digest)

    # Initialize the headers object to be returned via this method
    all_headers = {}
    # The content type of request
    all_headers['content-type'] = 'application/json'
    # The request target calculated above(reqt)
    all_headers['(request-target)'] = reqt
    # The date and time in GMT format
    all_headers['date'] = get_date
    # The host specified by the caller
    all_headers['host'] = get_host(host)
    all_headers['(created)'] = created
    all_headers['digest'] = digest
    headers = ['content-type', 'date', 'host', '(created)', '(request-target)', 'digest']

    # include the specified headers in the hmac calculation. each
    # header is of the form 'header_name: header value\n'
    # included headers are also added to an ordered list of headers
    # which is included in the message
    hmac = OpenSSL::HMAC.new(sapi, OpenSSL::Digest::SHA512.new)
    headers.each do |header|
      if all_headers.key?(header)
        hmac << "#{header}: #{all_headers[header]}\n"
      end
    end

    all_headers.delete('(created)')
    all_headers.delete('(request-target)')
    all_headers.delete('host')

    # Build the Signature header itself
    all_headers['signature']  = 'keyId="' + papi + '"'
    all_headers['signature'] += ', algorithm="hmac-sha512"'
    all_headers['signature'] += ', created=' + created.to_s
    all_headers['signature'] += ', headers="' + headers.join(" ") + '"'
    all_headers['signature'] += ', signature="'
    all_headers['signature'] += Base64.strict_encode64(hmac.digest)
    all_headers['signature'] += '"'

    return all_headers
  end

  def self.get_host(host)
    uri = URI(host)
    return "#{uri.hostname}:#{uri.port}"
  end

  def self.get_date
    DateTime.now.in_time_zone('GMT').strftime("%a, %d %b %Y") + " " + DateTime.now.in_time_zone('GMT').strftime("%H:%M:%S") + " GMT"
  end
end

class SecurityClient::Decryption
  def initialize(creds)
  # Initialize the decryption module object
  # Set the credentials in instance varibales to be used among methods
  # the server to which to make the request
  raise RuntimeError, 'Some of your credentials are missing, please check!' if !validate_creds(creds)
  @host = creds.host.blank? ? VOLTRON_HOST : creds.host

  # The client's public API key (used to identify the client to the server
  @papi = creds.access_key_id

  # The client's secret API key (used to authenticate HTTP requests)
  @sapi = creds.secret_signing_key

  # The client's secret RSA encryption key/password (used to decrypt the client's RSA key from the server). This key is not retained by this object.
  @srsa = creds.secret_crypto_access_key

  @decryption_ready = true
  @decryption_started = false

end

def endpoint_base
  @host + '/api/v0'
end

def endpoint
  '/api/v0/decryption/key'
end

def begin
  # Begin the decryption process

  # This interface does not take any cipher text in its arguments
  # in an attempt to maintain an API that corresponds to the
  # encryption object. In doing so, the work that can take place
  # in this function is limited. without any data, there is no
  # way to determine which key is in use or decrypt any data.
  #
  # this function simply throws an error if starting an decryption
  # while one is already in progress, and initializes the internal
  # buffer

  raise RuntimeError, 'Decryption is not ready' if !@decryption_ready

  raise RuntimeError, 'Decryption Already Started' if @decryption_started

  raise RuntimeError, 'Decryption already in progress' if @key.present? and @key.key?("dec")
  @decryption_started = true
  @data = ''
end

def update(data)
  # Decryption of cipher text is performed here
  # Cipher text must be passed to this function in the order in which it was output from the encryption.update function.

  # Each encryption has a header on it that identifies the algorithm
  # used  and an encryption of the data key that was used to encrypt
  # the original plain text. there is no guarantee how much of that
  # data will be passed to this function or how many times this
  # function will be called to process all of the data. to that end,
  # this function buffers data internally, when it is unable to
  # process it.
  #
  # The function buffers data internally until the entire header is
  # received. once the header has been received, the encrypted data
  # key is sent to the server for decryption. after the header has
  # been successfully handled, this function always decrypts all of
  # the data in its internal buffer *except* for however many bytes
  # are specified by the algorithm's tag size. see the end() function
  # for details.

  raise RuntimeError, 'Decryption is not Started' if !@decryption_started

  # Append the incoming data in the internal data buffer
  @data  = @data + data

  # if there is no key or 'dec' member of key, then the code is still trying to build a complete header
  if !@key.present? or !@key.key?("dec")
    struct_length = [1,1,1,1,1].pack('CCCCn').length
    packed_struct = @data[0...struct_length]

    # Does the buffer contain enough of the header to
    # determine the lengths of the initialization vector
    # and the key?
    if @data.length > struct_length
      # Unpack the values packed in encryption
      version, flag_for_later, algorithm_id, iv_length, key_length = packed_struct.unpack('CCCCn')

      # verify flag and version are 0
      raise RuntimeError, 'invalid encryption header' if version != 0 or flag_for_later != 0

      # Does the buffer contain the entire header?
      if @data.length > struct_length + iv_length + key_length
        # Extract the initialization vector
        iv = @data[struct_length...iv_length + struct_length]
        # Extract the encryped key
        encrypted_key = @data[struct_length + iv_length...key_length + struct_length + iv_length]
        # Remove the header from the buffer
        @data = @data[struct_length + iv_length + key_length..-1]

        # generate a local identifier for the key
        hash_sha512 = OpenSSL::Digest::SHA512.new
        hash_sha512 << encrypted_key
        client_id = hash_sha512.digest

        if @key.present?
          if @key['client_id'] != client_id
            close()
          end
        end

        # IF key object not exists, request a new one from the server
        if !@key.present?
          url = endpoint_base + "/decryption/key"
          query = {encrypted_data_key: Base64.strict_encode64(encrypted_key)}
          headers = Auth.build_headers(@papi, @sapi, endpoint, query, @host, 'post')

          response = HTTParty.post(
            url,
            body: query.to_json,
            headers: headers
          )

          # Response status is 200 OK
          if response.code == WEBrick::HTTPStatus::RC_OK
            @key = {}
            @key['finger_print'] = response['key_fingerprint']
            @key['client_id'] = client_id
            @key['session'] = response['encryption_session']

            @key['algorithm'] = 'aes-256-gcm'

            encrypted_private_key = response['encrypted_private_key']
            # Decrypt the encryped private key using SRSA
            private_key = OpenSSL::PKey::RSA.new(encrypted_private_key,@srsa)

            wrapped_data_key = response['wrapped_data_key']
            # Decode WDK from base64 format
            wdk = Base64.strict_decode64(wrapped_data_key)
            # Use private key to decrypt the wrapped data key
            dk = private_key.private_decrypt(wdk,OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)

            @key['raw'] = dk
            @key['uses'] = 0
          else
            # Raise the error if response is not 200
            raise RuntimeError, "HTTPError Response: Expected 201, got #{response.code}"
          end
        end

        # If the key object exists, create a new decryptor
        # with the initialization vector from the header and
        # the decrypted key (which is either new from the
        # server or cached from the previous decryption). in
        # either case, increment the key usage

        if @key.present?
          @algo = Algo.new.get_algo(@key['algorithm'])
          @key['dec'] = Algo.new.decryptor(@algo, @key['raw'], iv)
          @key['uses'] += 1
        end
      end
    end
  end

  # if the object has a key and a decryptor, then decrypt whatever
  # data is in the buffer, less any data that needs to be saved to
  # serve as the tag.
  plain_text = ''
  if @key.present? and @key.key?("dec")
    size = @data.length - @algo[:tag_length]
    if size > 0
      puts @data[0..size-1]

      plain_text = @key['dec'].update(@data[0..size-1])
      @data = @data[size..-1]
    end
    return plain_text
  end

end

def end
  raise RuntimeError, 'Decryption is not Started' if !@decryption_started
  # The update function always maintains tag-size bytes in
  # the buffer because this function provides no data parameter.
  # by the time the caller calls this function, all data must
  # have already been input to the decryption object.

  sz = @data.length - @algo[:tag_length]

  raise RuntimeError, 'Invalid Tag!' if sz < 0
  if sz == 0
    @key['dec'].auth_tag = @data
    begin
      pt = @key['dec'].final
      # Delete the decryptor context
      @key.delete('dec')
      # Return the decrypted plain data
      @decryption_started = false
      return pt
    rescue Exception => e
      print 'Invalid cipher data or tag!'
      return ''
    end
  end
end

  def close
    raise RuntimeError, 'Decryption currently running' if @decryption_started
    # Reset the internal state of the decryption object
    if @key.present?
      if @key['uses'] > 0
        query_url = "#{endpoint}/#{@key['finger_print']}/#{@key['session']}"
        url = "#{endpoint_base}/decryption/key/#{@key['finger_print']}/#{@key['session']}"
        query = {uses: @key['uses']}
        headers = Auth.build_headers(@papi, @sapi, query_url, query, @host, 'patch')
        response = HTTParty.patch(
          url,
          body: query.to_json,
          headers: headers
        )
        remove_instance_variable(:@data)
        remove_instance_variable(:@key)
      end
    end
  end

end
