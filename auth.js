import {GenerateTotpValue} from "totp_generator_hexadecimal";
import bcrypt from "bcrypt";
import crypto from "crypto";


export class Authenticator{
	/*Key : id, Value : Set<Token>*/
	#AuthTokensById = new Map();
	/*Key : Token, Value : {id : any, timeAdded : Number, timeExpires : Number, usages : Number}*/ 
	#AuthTokensByToken = new Map();

	constructor(init = {}){
		if (init.maxTokensPerId <= 0){
			throw new Error("max tokens can't be equal or lower to 0");
		}
		if (init.expiryTimeS < 5){
			throw new Error("Expiry time must be greater or equal to 5 seconds");
		}
		this.MaxTokensPerId = init.maxTokensPerId === undefined ? 10 : init.maxTokensPerId;
		this.ExpiryTimeS = init.expiryTimeS === undefined ? 604800 : init.expiryTimeS;
		this.BcryptHashRounds = init.bcryptHashRounds === undefined ? 12 : init.bcryptHashRounds;
		this.AuthTokenLength = init.authTokenLength === undefined ? 32 : init.authTokenLength;
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
		const timeNow = Math.floor(Date.now() / 1000);
		authTokenSet.add(token);
		this.#AuthTokensByToken.set(token,{id : id, timeAdded : timeNow, timeExpires : timeNow + expiry, usages : 0});
	}

	/*Creates a new authentication for the provided data, if the (user) provided values match<br>
	 * if id,totpValue,totpKey,passwordValue,hashedPassword is undefined it will throw<br>
	 * if expiryOverride is set it will override the default token expiry<br>
	 * returns undefined if the provided data doesn't match (totp or password)<br>
	 * returns a new auth token <Buffer> on success*/
	Authenticate = async function(id,passwordValue,hashedPassword,totpValue,totpKey,expiryOverride){
		if (id === undefined || passwordValue === undefined || hashedPassword === undefined || totpValue === undefined || totpKey === undefined){
			throw new Error("One or more input variables were undefined, make sure id,passwordValue,hashedPassword,totpValue,totpKey are all set");
		}

		if (await bcrypt.compare(passwordValue, hashedPassword) !== true){
			return undefined;
		}

		if (await GenerateTotpValue(totpKey) !== totpValue){
			return undefined;
		}

		const authToken = await randomBytesPromise(AuthTokenLength);
		await this.#AddAuthToken(authToken,id,expiryOverride);
		return authToken;
	}

	/* Checks the proivded auth token if it's valid (exists), returns (if valid) {id,timeAdded : Number,timeExpires : Number, usages : Number} or undefined if its invalid */
	CheckAuthToken = async function(token){
		const tokenData = this.#AuthTokensByToken.get(token);
		if (tokenData !== undefined){
			tokenData.usages++;
		}
		return tokenData;
	}

	/*Creates a new password Hash and totp Key, returns it in an object {hash : String(bcrypt) ,totpKey,String(hex)}<br>
	 * throws if password is undefined*/
	CreateHashAndTotp = async function(password){
		if (password === undefined){
			throw new Error("password can't be undefined");
		}

		return {hash : await bcrypt.hash(password,BcryptHashRounds), totpKey : crypto.randomBytes(20)}
	}
}


async function randomBytesPromise(len){
	return new Promise(async (resolve) => {
		crypto.randomBytes(len,(err,buff) => {
			resolve(buff);
		});
	});
}
