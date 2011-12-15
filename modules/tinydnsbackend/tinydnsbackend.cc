#include "tinydnsbackend.hh"
#include <pdns/dnslabel.hh>
#include <pdns/misc.hh>
#include <pdns/dnsrecords.hh>
#include <boost/foreach.hpp>

vector<string> CDB::findall(const string &key)
{
	vector<string> ret;
	struct cdb cdb;
	struct cdb_find cdbf; /* structure to hold current find position */

	int	fd = open(d_cdbfile.c_str(), O_RDONLY);

	cdb_init(&cdb, fd);
	fprintf(stderr, "key [%s] length [%d]\n", key.c_str(), key.size());
	fprintf(stderr, "cdb_findinit: %d\n", cdb_findinit(&cdbf, &cdb, key.c_str(), key.size()));
	cerr<<"doing cdb lookup of key ["<<makeHexDump(key)<<"]"<<endl;
	while(cdb_findnext(&cdbf) > 0) {
		unsigned int vpos = cdb_datapos(&cdb);
		unsigned int vlen = cdb_datalen(&cdb);
		char *val = (char *)malloc(vlen);
		cdb_read(&cdb, val, vlen, vpos);
		string sval(val, vlen);
		ret.push_back(sval);
		// cerr<<"got value ["<<makeHexDump(sval)<<"]"<<endl;
		free(val);
	}
	close(fd);
	return ret;
}

TinyDNSBackend::TinyDNSBackend()
{
	d_cdb=new CDB("/home/vagrant/data.cdb");
}

bool TinyDNSBackend::list(const string &target, int domain_id)
{
	return false;
}

void TinyDNSBackend::lookup(const QType &qtype, const string &qdomain, DNSPacket *pkt_p, int zoneId)
{
	DNSLabel l(qdomain.c_str());
	string key=l.binary();
	vector<string> res;

	L<<Logger::Debug<<"query for qtype "<<qtype.getName()<<" qdomain ["<<qdomain<<"]"<<endl;
	L<<Logger::Debug<<"key ["<<makeHexDump(key)<<"]"<<endl;
	d_qtype=qtype;
	d_values=d_cdb->findall(key);
}

bool TinyDNSBackend::get(DNSResourceRecord &r)
{
	BOOST_FOREACH(string val, d_values)
	{
		QType valtype;
		struct tinyrecord *rec;
		rec=(struct tinyrecord *) val.c_str();
		cerr<<"in get: got value ["<<makeHexDump(val)<<"]"<<endl;
		valtype = QType(ntohs(rec->type));
		cerr<<"value has qtype "<<valtype.getName()<<endl;
		cerr<<"query has qtype "<<d_qtype.getName()<<endl;
		if(d_qtype.getCode()==QType::ANY || valtype==d_qtype)
		{
			ostringstream content;

			cerr<<"WE GOT HIM"<<endl;
			string payload=val.substr(sizeof(struct tinyrecord));
			r.qtype=valtype;
			if(valtype.getCode() == QType::SOA)
			{
				SOARecordContent src(payload);

				cerr<<"SOA content: "<<src.getZoneRepresentation()<<endl;
			}
			cerr<<"payload: ["<<rec->payload<<"]"<<endl;
		}
	}
	return false;
}

// boilerplate
class TinyDNSFactory: public BackendFactory
{
public:
	TinyDNSFactory() : BackendFactory("tinydns") {}

	DNSBackend *make(const string &suffix)
	{
		return new TinyDNSBackend();
	}
};

// boilerplate
class TinyDNSLoader
{
public:
	TinyDNSLoader()
	{
		BackendMakers().report(new TinyDNSFactory);

		L<<Logger::Info<<" [TinyDNSBackend] This is the TinyDNSBackend ("__DATE__", "__TIME__") reporting"<<endl;
	}
};

static TinyDNSLoader tinydnsloader;
