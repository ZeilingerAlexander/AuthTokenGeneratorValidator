import {GenerateTotpValue} from "totp_generator_hexadecimal";
import bcrypt from "bcrypt";
import crypto from "crypto";


export class Authenticator{
	/*Key : id, Value : Set<Token>*/
	#AuthTokensById = new Map();
	/*Key : Token, Value : {id : any, timeAdded : Number, timeExpires : Number, usages : Number}*/ 
	#AuthTokensByToken = new Map();
	/*Key : id, Value : {totpKey,passwordHash}*/
	#SecretsByIdStore = new Map();

	constructor(init = {}){
		if (init.maxTokensPerId <= 0){
			throw new Error("max tokens can't be equal or lower to 0");
		}
		if (init.expiryTimeS < 5){
			throw new Error("Expiry time must be greater or equal to 5 seconds");
		}
		if (init.TotpKeySize < 20){
			throw new Error("cant go below the recommended totp key size, see https://datatracker.ietf.org/doc/html/rfc4226");
		}
		this.MaxTokensPerId = init.maxTokensPerId === undefined ? 10 : init.maxTokensPerId;
		this.ExpiryTimeS = init.expiryTimeS === undefined ? 604800 : init.expiryTimeS;
		this.BcryptHashRounds = init.bcryptHashRounds === undefined ? 12 : init.bcryptHashRounds;
		this.AuthTokenLength = init.authTokenLength === undefined ? 32 : init.authTokenLength;
		this.TotpKeySize = init.totpKeySize === undefined ? 32 : init.totpKeySize;
	}

	/*Adds a token with the provided identifier. If expiryOverride is set will override the default expiry Time<br>
	 * throws if token or id is undefined<br>
	 * Automaticly expires the least used token or soonest expiry if multiple if the auth token set for the id is full<br>
	 * Do not call this method directly, instead use Authenticate*/
	#AddAuthToken = async function(token,id,expiryOverride){
		if (token === undefined || id === undefined){
			throw new Error("Token and Id can't be undefined");
		}

		const authTokenSet = this.#AuthTokensById.get(id);
		if (authTokenSet === undefined){
			authTokenSet = new Set();
			this.#AuthTokensById.set(id,authTokenSet);
		}
		// remove the least used token (or soonest expiry if multiple) if limit has been reached
		if (authTokenSet.length >= this.MaxTokensPerId){
			const iterator = authTokenSet.values();
			const _firstEntryToken = iterator.next().value;
			const _firstEntry = this.#AuthTokensByToken.get(_firstEntryToken);
			let _currentLowestUsages = _firstEntry.usages;
			let _currentLowestRepeatedSoonestExpiry = _firstEntry.expiry; // fallback to expiry if multiple ones with the same use time
			let _currentLowestToken = _firstEntryToken;
			for (const token of iterator){
				const entry = this.#AuthTokensByToken.get(token);
				// usages lower or expires lower then current if reapeating the same usages
				if ((entry.usages < _currentLowestUsages)
					|| (entry.usages === _currentLowestUsages && entry.expiry < _currentLowestRepeatedSoonestExpiry)){
					_currentLowestUsages = entry.usages;
					_ = entry.expiry;
					_currentLowestToken = entry;
				}
			}
			this.#AuthTokensByToken.delete(_currentLowestToken);
			authTokenSet.delete(_currentLowestToken);
		}
		// add the token
		const expiry = expiryOverride === undefined ? this.ExpiryTimeS : expiryOverride;
		const timeNow = GetCurrentTime(); 
		authTokenSet.add(token);
		this.#AuthTokensByToken.set(token,{id : id, timeAdded : timeNow, timeExpires : timeNow + expiry, usages : 0});
	}

	/*Creates a new authentication for the provided data, if the (user) provided values match<br>
	 * This requires the secrets for id to be registered, if they are not it will throw, this can be avoided by providing secrets {passwordHash,totpKey} <br>
	 * if id,totp,password is undefined it will throw<br>
	 * if expiryOverride is set it will override the default token expiry<br>
	 * returns undefined if the provided data doesn't match (totp or password)<br>
	 * returns a new auth token <Buffer> on success*/
	Authenticate = async function(id,password,totp,secrets){
		if (id === undefined || password === undefined || totp === undefined){
			throw new Error("One or more input variables were undefined, make sure id,password and totp are all set");
		}

		let passwordAndTotp;
		if (secrets !== undefined){
			passwordAndTotp = secrets;
		}
		else{
			passwordAndTotp = this.#SecretsByIdStore.get(id);
		}
		if (passwordAndTotp === undefined || passwordAndTotp.totpKey === undefined || passwordAndTotp.passwordHash === undefined){
			throw new Error("Bad Secrets, either they weren't found or you provided bad ones. if you provided them they need to inlcude totpKey and passwordHash");
		}
		const passwordHash = passwordAndTotp.passwordHash;
		const totpKey = passwordAndTotp.totpKey;

		if (await bcrypt.compare(password, passwordHash) !== true){
			return undefined;
		}

		if (await GenerateTotpValue(totpKey) !== totp){
			return undefined;
		}

		const authToken = await randomBytesPromise(AuthTokenLength);
		await this.#AddAuthToken(authToken,id,expiryOverride);
		return authToken;
	}

	/*expires a token for the provided token, throws if undefined*/
	ExpireAuthToken = function(token){
		if (token === undefined){
			throw new Error("token can't be undefined");
		}
		const tokenData = this.#AuthTokensByToken.get(token);
		if (tokenData !== undefined){
			const tokenSetForId = this.#AuthTokensById.get(tokenData.id);
			if (tokenSetForId !== undefined){
				tokenSetForId.delete(token);
			}
			this.#AuthTokensByToken.delete(token);
		}
	}

	/*expires all auth tokens for the provided id, throws if id undefined*/
	ExpireAllAuthTokens = function(id){
		if (id === undefined){
			throw new Error("id can't be undefined");
		}
		const tokenSet = this.#AuthTokensById.get(id);
		if (tokenSet !== undefined){
			for (const token of tokenSet){
				this.#AuthTokensByToken.delete(token);
			}
			tokenSet.clear();
		}
	}

	/* Checks the proivded auth token if it's valid (exists and not expired), returns (if valid) {id,timeAdded : Number,timeExpires : Number, usages : Number} or undefined if its invalid<br>
	 * Expires tokens if their timeExpires is before the current time (it expired)*/
	CheckAuthToken = function(token){
		const tokenData = this.#AuthTokensByToken.get(token);
		if (tokenData !== undefined){
			tokenData.usages++;
			if (tokenData.timeExpires < GetCurrentTime()){
				ExpireAuthToken(token);
				return undefined;
			}
		}
		return tokenData;
	}

	/*Checks if there is a secret with the provided Identifier, returns true/false*/
	CheckIfSecretIsRegisterWithIdentifier = function(id){
		return this.#SecretsByIdStore.has(id);
	}

	/*Removes Secrets with the provided id*/
	RemoveSecrets = function (id){
		this.#SecretsByIdStore.delete(id);
	}

	/*Registers the provided secrets to the identifier provided, throws if any undefined, returns true if the secrets were added, false if the identifier is already in the secret store*/
	RegisterSecrets = function(id,passwordHash,totpKey){
		if (id === undefined || passwordHash === undefined || totpKey === undefined){
			throw new Error("id,passwordHash and totpKey can't be undefined");
		}
		if (this.#SecretsByIdStore.has(id) === false){
			this.#SecretsByIdStore.set(id,{passwordHash : passwordHash, totpKey : totpKey});
			return true;
		}
		else{
			return false;
		}
	}

	/*Creates a new password Hash and totp Key, returns it in an object {hash : String(bcrypt) ,totpKey,String(hex)}<br>
	 * throws if password is undefined*/
	CreateHashAndTotp = async function(password){
		if (password === undefined){
			throw new Error("password can't be undefined");
		}

		return {hash : await bcrypt.hash(password,this.BcryptHashRounds), totpKey : crypto.randomBytes(this.TotpKeySize)}
	}
}


async function randomBytesPromise(len){
	return new Promise(async (resolve) => {
		crypto.randomBytes(len,(err,buff) => {
			resolve(buff);
		});
	});
}

function GetCurrentTime(){
	return Math.floor(Date.now() / 1000);
}
