#ifndef TINYDNSBACKEND_HH
#define TINYDNSBACKEND_HH

#include <pdns/dnsbackend.hh>
#include <pdns/logger.hh>
#include <cdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

class CDB
{
public:
	CDB(const string &cdbfile) : d_cdbfile(cdbfile)	{}
	~CDB();

	vector<string> findall(const string &key);

private:
	const string d_cdbfile;
};

class TinyDNSBackend : public DNSBackend
{
public:
	TinyDNSBackend();
	// ~TinyDNSBackend();
	void lookup(const QType &qtype, const string &qdomain, DNSPacket *pkt_p=0, int zoneId=-1);
	bool list(const string &target, int domain_id);
	bool get(DNSResourceRecord &rr);
	// bool getSOA(const string &name, SOAData &soadata, DNSPacket *p=0);
private:
	int d_fd;
	QType d_qtype;
	CDB *d_cdb;
	vector<string> d_values;
	string d_qdomain;
};

struct tinyrecord
{
	uint16_t type;
	uint8_t wild;
	uint32_t ttl;
	uint64_t timestamp;
	char payload[];
} __attribute__((packed));

#endif // TINYDNSBACKEND_HH 