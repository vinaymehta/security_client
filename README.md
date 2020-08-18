# SecurityClient

Welcome to your new gem! In this directory, you'll find the files you need to be able to package up your Ruby library into a gem. Put your Ruby code in the file `lib/security_client`. To experiment with that code, run `bin/console` for an interactive prompt.

TODO: Delete this and the text above, and describe your gem

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'security_client'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install security_client

## Usage

```ruby
  # Initialize the Client
  client = SecurityClient::Voltron.new(
    access_key_id: 'Your access key',
    secret_signing_key: 'Your secret signing key',
    secret_crypto_access_key: 'Your secret crypto access key',
    host: 'Your host'
  )

  # Simple Encryption
  encrypted_result = client.encrypt(
    uses: 'Key Uses',
    data: 'Data to be encrypted'
  )

  # Simple Decryption
  original_data = client.decrypt(
    data: 'Encrypted Data'
  )

  # Piecewise Encryption
    # Get your credentials ready
    credentials = OpenStruct.new(
      access_key_id: 'Your access key',
      secret_signing_key: 'Your secret signing key',
      secret_crypto_access_key: 'Your secret crypto access key',
      host: 'Your host'
    )

    # Build the encryption object
    enc = SecurityClient::Encryption.new(credentials, uses)
    # Begin the encryption
    enc.begin()
    # Update the cipher with the raw data, can be supplied directly or in chunks
    enc.update(data)
    # End the encryption
    enc.end()
    # Reset the encryption object to initial state and cleanup the memory in use
    enc.close()

  # Piecewise Decryption
    # Get your credentials ready
    credentials = OpenStruct.new(
      access_key_id: 'Your access key',
      secret_signing_key: 'Your secret signing key',
      secret_crypto_access_key: 'Your secret crypto access key',
      host: 'Your host'
    )

    # Build the decryption object
    dec = SecurityClient::Decryption.new(credentials)
    # Begin the decryption
    dec.begin()
    # Update the cipher with the raw data, can be supplied directly or in chunks
    dec.update(data)
    # End the decryption
    dec.end()
    # Reset the decryption object to initial state and cleanup the memory in use
    dec.close()

```

## Development

After checking out the repo, run `bin/setup` to install dependencies. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/[USERNAME]/security_client. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.

## Code of Conduct

Everyone interacting in the SecurityClient project’s codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/[USERNAME]/security_client/blob/master/CODE_OF_CONDUCT.md).
