json.array!(@articles) do |article|
  json.extract! article, :id, :title, :body, :password_digest
  json.url article_url(article, format: :json)
end
