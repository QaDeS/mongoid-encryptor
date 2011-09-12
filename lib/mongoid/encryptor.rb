# -*- encoding: utf-8 -*-
require 'encrypted_strings'

module Mongoid #:nodoc:

  # mongoid-encryptor encrypts and decrypts one or more fields in a Mongoid model.
  module Encryptor
    extend ActiveSupport::Concern

    module ClassMethods #:nodoc:
      # @param [Hash] opts
      def encrypted(*args)
        opts = args.extract_options!
        defined_attrs = fields.keys
        yield if block_given?
        attrs = (fields.keys - defined_attrs + args).uniq
        attrs << opts
        encrypts(*attrs)
      end

      # @param [Hash] attrs
      def encrypts(*attrs)
        base_options = attrs.last.is_a?(Hash) ? attrs.pop : {}

        attrs.each do |attr_name|
          options = base_options.dup
          attr_name = attr_name.to_s

          mode = options.delete(:mode) || :sha
          cipher_class = EncryptedStrings.const_get("#{mode.to_s.classify}Cipher")

          send(:after_validation) do |doc|
            doc.send(:write_encrypted_attribute, attr_name, cipher_class, options)
            true
          end

          define_method(attr_name) do
            read_encrypted_attribute(attr_name, cipher_class, options)
          end
        end
      end
    end

    module InstanceMethods #:nodoc:
      # Returns decrypted value for key.
      #
      # @param [String] key
      # @return [Object]
      def read_attribute_for_validation(key)
        v = read_attribute(key) || instance_variable_get("@#{key}")
        (v.respond_to?(:can_decrypt?) && v.can_decrypt?) ? v.decrypt : v
      end

      private

      # @param [String] attr_name
      # @param [Class] cipher_class
      # @param [Hash] options
      def write_encrypted_attribute(attr_name, cipher_class, options)
        value = read_attribute(attr_name.to_sym)
        return if value.blank? or value.encrypted?

        cipher = instantiate_cipher(cipher_class, options)
        value = cipher.encrypt(value)
        value.cipher = cipher
        send("#{attr_name}=", value)
      end

      # @param [String] attr_name
      # @param [Class] cipher_class
      # @param [Hash] options
      # @return [String]
      def read_encrypted_attribute(attr_name, cipher_class, options)
        value = read_attribute(attr_name)

        unless value.blank? || value.encrypted? || attribute_changed?(attr_name) || new_record?
          value.cipher = instantiate_cipher(cipher_class, options)
        end

        value
      end

      # @param [Class] cipher_class
      # @param [Hash] options
      # @return [EncryptedStrings::Cipher]
      def instantiate_cipher(cipher_class, options)
        opts = options.dup
        opts.each_pair do |k, v|
          opts[k] = v.bind(self) if v.is_a?(Proc)
        end
        cipher_class.new(opts)
      end
    end
  end

end
