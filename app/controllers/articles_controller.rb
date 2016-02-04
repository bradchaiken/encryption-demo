class ArticlesController < ApplicationController
  require 'sha3'
  before_action :set_article, only: [:show, :edit, :update, :destroy]

  def index
    @articles = Article.all
  end

  def show
    authenticate_article_access

    # Decrypt password for display.
    key = ActiveSupport::KeyGenerator.new(Rails.application.secrets.password_digest_secret).generate_key(Rails.application.secrets.password_digest_salt)
    crypt = ActiveSupport::MessageEncryptor.new(key, digest: "SHA384")
    @decrypted_pass = crypt.decrypt_and_verify(@article.password_digest)
  end

  def new
    @article = Article.new
  end

  def edit
  end

  def create
    @article = Article.new(article_params)
    # Encrypt password_digest
    result = EncryptArticleAccessPassword.call(article: @article)
    # If the result is a success,
    # and the @article object passes validation, create the object.
    if result.success?
      if @article.save
        redirect_to @article, notice: "The article has been successfully created."
      else
        render action: "new", error: "There was an error creating this article."
      end
    else
      flash.now[:error] = result.error
      render 'new'
    end
  end

  def update
    # Decrypt old password
    key = ActiveSupport::KeyGenerator.new(Rails.application.secrets.password_digest_secret).generate_key(Rails.application.secrets.password_digest_salt)
    crypt = ActiveSupport::MessageEncryptor.new(key)
    decrypted_pass = crypt.decrypt_and_verify(@article.password_digest)

    # Compare the decrypted password with the params given.
    # If they are different, than we need to update the new password.
    if @article.password_digest != params[:article][:password_digest].to_s
      # Encrypt the new password...
      encrypted_password_digest = crypt.encrypt_and_sign(params[:article][:password_digest])
      # Create new params out of an @article object...
      new_article_params = @article.attributes
      # Set the new hashed, salted password...
      new_article_params[:password_digest] = encrypted_password_digest
      # Update the Article object.
      if @article.update_attributes(new_article_params)
        redirect_to @article, notice: "The article has been successfully updated."
      else
        render action: "edit"
      end
    else
      if @article.update_attributes(article_params)
        redirect_to @article, notice: "The article has been successfully updated."
      else
        render action: "edit"
      end
    end

  end

  def destroy
    @article.destroy
    respond_to do |format|
      format.html { redirect_to articles_url, notice: 'Article was successfully destroyed.' }
      format.json { head :no_content }
    end
  end

  private

    def authenticate_article_access
      # Set secret token and salt for key.
      key = ActiveSupport::KeyGenerator.new(Rails.application.secrets.password_digest_secret).generate_key(Rails.application.secrets.password_digest_salt)
      crypt = ActiveSupport::MessageEncryptor.new(key, digest: "SHA384")
      decrypted_pass = crypt.decrypt_and_verify(@article.password_digest)
      # Set the article title for the article pass name.
      article_title = @article.title
      # Authenticate the user.
      initialize_basic_auth(article_title, decrypted_pass)
    end

    def initialize_basic_auth(article_title, decrypted_password)
      authenticate_or_request_with_http_basic('Administration') do |username, password|
        username == article_title && password == decrypted_password
      end
    end

    # Use callbacks to share common setup or constraints between actions.
    def set_article
      @article = Article.find(params[:id])
    end

    # Never trust parameters from the scary internet, only allow the white list through.
    def article_params
      params.require(:article).permit(:title, :body, :password_digest)
    end
end
