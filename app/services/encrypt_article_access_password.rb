class EncryptArticleAccessPassword

  include Interactor

  before do
    context.fail!(error: "You must specify a article.") if context.article.blank?
  end

  def call
    # Set secret and salt for key from rails secrets.
    key = ActiveSupport::KeyGenerator.new(Rails.application.secrets.password_digest_secret).generate_key(Rails.application.secrets.password_digest_salt)
    crypt = ActiveSupport::MessageEncryptor.new(key, digest: "SHA384")

    puts "\n\n"
    puts "********************************************************************************"
    puts "                              OUR KEY"
    puts "--------------------------------------------------------------------------------"
    ap key

    puts "\n\n"
    puts "********************************************************************************"
    puts "                              OUR CRYPT"
    puts "--------------------------------------------------------------------------------"
    ap crypt

    # Encrypt password.
    encrypted_password_digest = crypt.encrypt_and_sign(context.article.password_digest)

    puts "\n\n"
    puts "********************************************************************************"
    puts "                              OUR NEW ENCRYPTED PASSWORD"
    puts "--------------------------------------------------------------------------------"
    ap encrypted_password_digest

    context.article.password_digest = encrypted_password_digest
  end

end

def rollback
end