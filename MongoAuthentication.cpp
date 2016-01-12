#include <cstdint>
#include <Poco/MD5Engine.h>
#include <Poco/HMACEngine.h>
#include <Poco/RandomStream.h>
#include <Poco/Random.h>
#include <Poco/Base64Encoder.h>
#include <Poco/Base64Decoder.h>
#include <Poco/MongoDB/Binary.h>
#include <Poco/Dynamic/Var.h>
#include <Poco/MemoryStream.h>
#include "MongoAuthentication.h"

using namespace Poco;
using namespace Poco::MongoDB;

MongoAuthentication::MongoAuthentication(Poco::MongoDB::Connection &conn, Poco::MongoDB::Database &db) : _conn(conn), _db(db)
{

}

bool MongoAuthentication::authenticateMongoCR(const std::string &user, const std::string &pwd)
{
	bool ret = false;
	_user = user;
	_pwd = pwd;

	try {
		std::string nonce;
		Poco::SharedPtr<Poco::MongoDB::QueryRequest> command = _db.createCommand();
		command->selector().add<Poco::Int32>("getnonce", 1);
		command->setNumberToReturn(1);

		Poco::MongoDB::ResponseMessage response;
		_conn.sendRequest(*command, response);

		if (response.documents().size() > 0) {
			Poco::MongoDB::Document::Ptr doc = response.documents()[0];
			nonce = doc->get<std::string>("nonce", "");

			std::string password = _user + ":mongo:" + _pwd;

			Poco::MD5Engine md5;
			md5.update(password);
			std::string hashedPassword(Poco::DigestEngine::digestToHex(md5.digest()));
			std::string key = nonce + _user + hashedPassword;
			md5.reset();
			md5.update(key);
			std::string hashedKey(Poco::DigestEngine::digestToHex(md5.digest()));


			Poco::SharedPtr<Poco::MongoDB::QueryRequest> command = _db.createCommand();
			command->selector()
				.add<Poco::Int32>("authenticate", 1)
				.add<std::string>("user", _user)
				.add<std::string>("nonce", nonce)
				.add<std::string>("key", hashedKey);      // hex_md5( n.nonce + username + hex_md5( username + ":mongo:" + password ) )

			_conn.sendRequest(*command, response);

			if (response.documents().size() > 0 && response.documents()[0]->get<double>("ok")) {
				ret = true;
			}
		}
	} catch (Poco::Exception &) {
		throw Poco::ApplicationException("auth failed.");
	}

	return ret;
}


bool MongoAuthentication::authenticateSCRAM(const std::string &user, const std::string &pwd)
{
	static const std::size_t maxAuthMsg = 4096;

	bool ret = false;
	_user = user;
	_pwd = pwd;

	UCBuffer buf(maxAuthMsg);
	UCBuffer payload(maxAuthMsg);
	buf.resize(0);
	payload.resize(0);

	SharedPtr<QueryRequest> cmd = _db.createCommand();
	ResponseMessage rsp;

	scramStart(buf, payload);
	Binary::Ptr pl(new Binary);
	pl->buffer() = payload;
	cmd->selector().add("saslStart", 1).add("mechanism", "SCRAM-SHA-1").add("payload", pl);
	_conn.sendRequest(*cmd, rsp);

	if (rsp.hasDocuments() && rsp.documents()[0]->get<double>("ok")) {
		Document::Ptr doc = rsp.documents()[0];
		payload.resize(0);
		payload.append(doc->get<Binary::Ptr>("payload")->buffer());
		scramStep2(buf, payload);

		cmd->selector().clear();
		pl->buffer().resize(0);
		pl->buffer().append(payload);
		cmd->selector().add("saslContinue", 1).add("payload", pl).add("conversationId", doc->get<int32_t>("conversationId"));
		_conn.sendRequest(*cmd, rsp);

		if (rsp.hasDocuments() && rsp.documents()[0]->get<double>("ok")) {
			// TODO scram step3 :验证服务器响应是否正确

			// 发送final消息
			doc = rsp.documents()[0];
			cmd->selector().clear();
			cmd->selector().add("saslContinue", 1).add("payload", "").add("conversationId", doc->get<int32_t>("conversationId"));
			_conn.sendRequest(*cmd, rsp);
			if (rsp.hasDocuments() && rsp.documents()[0]->get<bool>("done")) ret = true;
		}	
	}

	return ret;
}

void MongoAuthentication::scramStart(UCBuffer &authMsg, UCBuffer &payload)
{
	std::stringstream noceStream;

	noceStream << "n,,n=" << _user << ",r=";
	Poco::RandomInputStream rs;
	char buf[24] = { 0 };
	rs.rdbuf()->readFromDevice(buf, sizeof(buf));
	Poco::Base64Encoder b64(noceStream);
	b64.write(buf, sizeof(buf));
	b64.close();
	payload.clear();
	payload.append((const unsigned char*)noceStream.str().c_str(), noceStream.str().size());
	authMsg.append(payload.begin() + 3, payload.size() - 3);  // 从“n=”开始保存所有auth消息
	authMsg.append(',');
}

void MongoAuthentication::scramStep2(UCBuffer &authMsg, UCBuffer &payload)
{
	// 首先将服务端返回的payload存入到authMsg中
	authMsg.append(payload);
	authMsg.append(',');

	// 找出r,s,i
	int32_t rPos = 0, sPos = 0, iPos = 0, p = 0, length = (int32_t)payload.size();
	for (; p < length; p++) {
		if ('r' == payload[p] && '=' == payload[p + 1]) {
			p++;
			p++;
			rPos = p;
			break;
		}
	}
	for (; p < length; p++) {
		if ('s' == payload[p] && '=' == payload[p + 1]) {
			p++;
			p++;
			sPos = p;
			break;
		}
	}
	for (; p < length; p++) {
		if ('i' == payload[p] && '=' == payload[p + 1]) {
			p++;
			p++;
			iPos = p;
			break;
		}
	}

	int rLen = sPos - rPos - 3;
	int sLen = iPos - sPos - 3;
	int iLen = (int)payload.size() - iPos;

	uint8_t *r = new uint8_t[rLen], *s = new uint8_t[sLen];
	char *i = new char[iLen + 1];

	memcpy(r, payload.begin() + rPos, rLen);
	memcpy(s, payload.begin() + sPos, sLen);
	memcpy(i, payload.begin() + iPos, iLen);
	i[iLen] = '\0';

	std::string var(i);
	Poco::Dynamic::Var varI(var);
	int iterations = varI.convert<int>();

	std::string password = _user + ":mongo:" + _pwd;
	Poco::MD5Engine md5;
	md5.update(password);
	std::string hasedPassword = DigestEngine::digestToHex(md5.digest());

	payload.resize(0);
	payload.append((unsigned char*)"c=biws,r=", strlen("c=biws,r="));
	payload.append(r, rLen);
	authMsg.append(payload);
	payload.append((unsigned char*)",p=", strlen(",p="));

	Poco::MemoryInputStream saltStream((char*)s, sLen);
	Poco::Base64Decoder b64(saltStream);
	std::stringstream sstream;
	char decodeSalt[16] = { 0 };
	std::stringbuf *buf = sstream.rdbuf();
	b64 >> buf;
	std::streamsize size = buf->pubseekoff(0, sstream.end);
	buf->pubseekoff(0, sstream.beg);
	buf->sgetn(decodeSalt, size);

	uint8_t saltedPassword[SHA1Engine::DIGEST_SIZE] = { 0 };

	scramSaltPassword(saltedPassword, hasedPassword, decodeSalt, sizeof(decodeSalt), iterations);
	scramGenerateClientProof(authMsg, payload, saltedPassword);
}


void MongoAuthentication::scramSaltPassword(uint8_t saltedPassword[SHA1Engine::DIGEST_SIZE], const std::string &hasedPassword, char* salt, int saltLen, int iterations)
{
	int i = 0, n = 0, k = 0;
	char startKey[SHA1Engine::DIGEST_SIZE] = { 0 };
	memcpy(startKey, salt, saltLen);
	startKey[saltLen] = 0;
	startKey[saltLen + 1] = 0;
	startKey[saltLen + 2] = 0;
	startKey[saltLen + 3] = 1;

	HMACEngine<SHA1Engine> hmac(hasedPassword);
	hmac.update(startKey, sizeof(startKey));
	const DigestEngine::Digest& digest = hmac.digest();

	uint8_t intermediateDigest[SHA1Engine::DIGEST_SIZE] = { 0 };
	for (i = 0; i < hmac.digestLength(); i++) {
		saltedPassword[i] = intermediateDigest[i] = digest[i];
	}

	for (i = 2; i <= iterations; i++) {
		HMACEngine<SHA1Engine> hmac(hasedPassword);
		hmac.update(intermediateDigest, sizeof(intermediateDigest));
		const DigestEngine::Digest& digest = hmac.digest();
		for (n = 0; n < SHA1Engine::DIGEST_SIZE; n++) {
			intermediateDigest[n] = digest[n];
			
		}
		for (k = 0; k < SHA1Engine::DIGEST_SIZE; k++) {
			saltedPassword[k] ^= intermediateDigest[k];
		}
	}
}

void MongoAuthentication::scramGenerateClientProof(UCBuffer &authMsg, UCBuffer &payload, uint8_t saltedPassword[Poco::SHA1Engine::DIGEST_SIZE])
{
	uint8_t clientKey[SHA1Engine::DIGEST_SIZE] = { 0 };
	uint8_t storedKey[SHA1Engine::DIGEST_SIZE] = { 0 };
	uint8_t clientSignature[SHA1Engine::DIGEST_SIZE] = { 0 };
	uint8_t clientProof[SHA1Engine::DIGEST_SIZE] = { 0 };

	HMACEngine<SHA1Engine> hmac((char*)saltedPassword, SHA1Engine::DIGEST_SIZE);
	hmac.update("Client Key", strlen("Client Key"));
	const DigestEngine::Digest& clientDigest = hmac.digest();
	for (int i = 0; i < clientDigest.size(); i++) {
		clientKey[i] = clientDigest[i];
	}

	SHA1Engine sha;
	sha.update(clientKey, SHA1Engine::DIGEST_SIZE);
	const DigestEngine::Digest &storedDigest = sha.digest();
	for (int i = 0; i < storedDigest.size(); i++) {
		storedKey[i] = storedDigest[i];
	}

	HMACEngine<SHA1Engine> hmac2((char*)storedKey, sizeof(storedKey));
	hmac2.update(authMsg.begin(), authMsg.size());
	const DigestEngine::Digest &signatrueDigest = hmac2.digest();
	for (int i = 0; i < signatrueDigest.size(); i++) {
		clientSignature[i] = signatrueDigest[i];
	}

	for (int i = 0; i < SHA1Engine::DIGEST_SIZE; i++) {
		clientProof[i] = clientKey[i] ^ clientSignature[i];
	}

	std::stringstream proofStream;
	Poco::Base64Encoder b64(proofStream);
	b64.write((char*)clientProof, sizeof(clientProof));
	b64.close();
	payload.append((unsigned char*)proofStream.str().c_str(), proofStream.str().size());
}

bool MongoAuthentication::scramFinal()
{
	return true;
}