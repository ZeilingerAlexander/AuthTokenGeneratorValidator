import {GenerateTotpValue} from "totp_generator_hexadecimal";
import {Authenticator} from "../../auth.js";
import bcrypt from "bcrypt";

test("CreateHashAndTotp should return correct values", async () => {
	const auth = new Authenticator();
	const pass = "super duper secret";
	const hashAndTotp = await auth.CreateHashAndTotp(pass);
	expect(hashAndTotp).toBeDefined();
	expect(hashAndTotp.passwordHash).toBeDefined();
	expect(hashAndTotp.totpKey).toBeDefined();
	expect(hashAndTotp.totpKey.length).toBe(auth.TotpKeySize);
	expect(bcrypt.compareSync(pass,hashAndTotp.passwordHash)).toBe(true);
});

test("Authenticate with directly passed secrets should return a working auth token", async () => {
	const auth = new Authenticator();
	const pass = "super duper secret";
	const hashAndTotp = await auth.CreateHashAndTotp(pass);
	const authToken = await auth.Authenticate(1,pass,await GenerateTotpValue(hashAndTotp.totpKey),{ secrets : hashAndTotp});
	expect(authToken.length).toBe(auth.AuthTokenLength);
	// validate if auth token actually works
	expect(auth.CheckAuthToken(authToken)).toBeDefined();
});

test("Register secrets should actually register them", async () => {
	const auth = new Authenticator();
	const hashAndTotp = await auth.CreateHashAndTotp("secure");
	auth.RegisterSecrets(1,hashAndTotp.passwordHash,hashAndTotp.totpKey);
	expect(auth.CheckIfSecretIsRegisterWithIdentifier(1)).toBe(true);
});

test("Remove Secret should remove the secret", async () => {
	const auth = new Authenticator();
	const hashAndTotp = await auth.CreateHashAndTotp("secure");
	auth.RegisterSecrets(1,hashAndTotp.passwordHash,hashAndTotp.totpKey);
	expect(auth.CheckIfSecretIsRegisterWithIdentifier(1)).toBe(true);
	auth.RemoveSecrets(1);
	expect(auth.CheckIfSecretIsRegisterWithIdentifier(1)).toBe(false);
});

test("Authentication with registered secred should return a working auth token", async () => {
	const auth = new Authenticator();
	const pass = "super duper secret";
	const hashAndTotp = await auth.CreateHashAndTotp(pass);
	auth.RegisterSecrets(1,hashAndTotp);
	const authToken = await auth.Authenticate(1,pass,await GenerateTotpValue(hashAndTotp.totpKey));
	expect(authToken.length).toBe(auth.AuthTokenLength);
	// validate if auth token actually works
	expect(auth.CheckAuthToken(authToken)).toBeDefined();
});

test("Bad auth tokens should not give a valid auth", async () => {
	const auth = new Authenticator();
	expect(auth.CheckAuthToken("not me")).toBe(undefined);
	expect(auth.CheckAuthToken("s98fdysdiufhsHI*HI")).toBe(undefined);
});
