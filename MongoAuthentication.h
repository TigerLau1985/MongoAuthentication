#ifndef __CTGW_INC_MONGOAUTHENTICATION_H
#define __CTGW_INC_MONGOAUTHENTICATION_H

#include <Poco/MongoDB/Connection.h>
#include <Poco/MongoDB/Database.h>
#include <Poco/SHA1Engine.h>
#include <Poco/Buffer.h>


class MongoAuthentication
{
public:
	typedef Poco::Buffer<unsigned char> UCBuffer;
	explicit MongoAuthentication(Poco::MongoDB::Connection &conn, Poco::MongoDB::Database &db);
	bool authenticateMongoCR(const std::string &user, const std::string &pwd);
	bool authenticateSCRAM(const std::string &user, const std::string &pwd);

protected:
	void scramStart(UCBuffer &authMsg, UCBuffer &payload);
	void scramSaltPassword(uint8_t saltedPassword[Poco::SHA1Engine::DIGEST_SIZE], const std::string &hasedPassword, char* salt, int saltLen, int iterations);
	void scramGenerateClientProof(UCBuffer &authMsg, UCBuffer &payload, uint8_t saltedPassword[Poco::SHA1Engine::DIGEST_SIZE]);
	void scramStep2(UCBuffer &authMsg, UCBuffer &payload);
	bool scramFinal();
private:
	Poco::MongoDB::Connection		&_conn;
	Poco::MongoDB::Database			&_db;
	std::string						_user;
	std::string						_pwd;
};

#endif