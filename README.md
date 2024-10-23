# Auth Token Generator and Validator
## Usage
```js
import {Authenticator} from "2fauth-lib";

const passkey = "super secret";
const userId = 1; // Identifier can be anything
const auth = new Authenticator();
// creates the bcrypt hash and totp, you can of course create them yourself without this method
const hashAndTotp = await auth.CreateHashAndTotp(passkey);
// hashAndTotp = {passwordHash,totpKey}

// register the secrets so we don't have to pass them on each authentication call
auth.RegisterSecrets(userId,hashAndTotp);

// do some work getting the users input
const userProvidedPassword = "super secret";
const userProvidedTotpValue = 123456;

// won't work and returns undefined since totp is wrong but you get the gist of it here
const token = await auth.Authenticate(userId,userProvidedPassword,userProvidedTotpValue);

// if you did not register the secrets you can also opt to pass them into the optional parameters
const token = await auth.Authenticate(userId,userProvidedPassword,userProvidedTotpValue,{secrets : hashAndTotp});

// if you want to validate an auth token a user provided you can use :
// do some work to get the auth token
const userAuthToken = "Gibberish";
const authData = auth.CheckAuthToken(userAuthToken);
// authData = {id,timeAdded,timeExpires,usages} or undefined if not valid

// if you no longer wish to use an auth token you can expire it early
auth.ExpireAuthToken(token);
// or you can expire all auth tokens for a specific id
auth.ExpireAllAuthTokens(userId);

// if you want to remove a Secret from a user you can use
auth.RemoveSecrets(userId);

// if you want to check if the user has a secret you can use
if (auth.CheckIfSecretIsRegisterWithIdentifier(userId){
    console.log("user has a secret");
}
```

## constructor parameters
The constructor of the <code>Authenticator</code> class accepts an object as parameters, this object can have multiple properties, if they are not set the default is used.
1. maxTokensPerId : Number, default : 10, minimum : 1
2. expiryTimeS : Number, default : 604800 (1 week), minimum : 5
3. bcryptHashRounds : Number, default : 12
4. authTokenLength : Number, default : 32
5. totpKeySize : Number, default : 32, minimum : 20
