# Latest and error free guide on how to secure GoLang API using JWT.

## Following are the important parts in the code you may want to note:

1) Line 25 and 26: As per the new changes, the RSA key (in this case) for verification should be of type `*rsa.PublicKey` and in case of signing it should be of type `*rsa.PrivateKey`.

2) Line 97 - 107: claims are made in a new way. Earlier it was:
```Go
t := jwt.New(jwt.GetSigningMethod("RS256"))
t.Claims["iss"] = "admin"
```
##### Now...
```Go
signer := jwt.New(jwt.GetSigningMethod("RS256"))
        
claims := signer.Claims.(jwt.MapClaims)
        
claims["iss"] = "admin"
```
3) Line 130 `ParseFromRequest()` is transferred from jwt package to **request** package. Since bearer token authorization is used (Authorization: Bearer \<token>) `request.AuthorizationHeaderExtractor` is used to extract the token.
    
