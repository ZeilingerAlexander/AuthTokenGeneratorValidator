import * as http from "node:http";
import {promises as fsp} from "fs";
import https from "node:https";

let /*Map<string>*/AllowedIpAddresses;
const RequestRoutes = new Map([]);

/*Starts the http server. leave sllKeyPath undefined (3rd param) to start via http*/
export async function StartServer(port,/*Map<string>*/allowedIpAddresses,sslKeyPath,sslCertificatePath){
	if (allowedIpAddresses === undefined || allowedIpAddresses.constructor.name !== "Map"){
		throw new Error("Expected a Map of Allowed Ip Addresses but recieved " + allowedIpAddresses.constructor.name);
	}
	AllowedIpAddresses = allowedIpAddresses;

	const server = undefined;
	if (sslKeyPath === undefined){
		console.warn("WARNING : STARTED AUTH SERVER USING HTTP");
		console.warn("WARNING : STARTED AUTH SERVER USING HTTP");
		console.warn("WARNING : STARTED AUTH SERVER USING HTTP");
		server = http.createServer(onServerRequest);
	}
	else{
		const options = {
			key : await fsp.readFile(sslKeyPath),
			cert : await fsp.readFile(sslCertificatePath)
		}
		server = https.createServer(options,onServerRequest);
	}
	server.listen(port);
}

async function onServerRequest(/*module:http.IncomingMessage*/req,/*module:http.ServerResponse<Request>*/res){
	if (AllowedIpAddresses.has(req.socket.remoteAddress)){
		const endpoint = req.
	}
}
