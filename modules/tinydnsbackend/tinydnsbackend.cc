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
	d_cdb=new CDB("/tmp/data.cdb");
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
	d_qdomain = qdomain;
}

bool TinyDNSBackend::get(DNSResourceRecord &rr)
{
	if(!d_values.size())
	{
		return false;
	}
	else
	{
		next:
			string val = d_values.back();
			d_values.pop_back();
			QType valtype;
			vector<uint8_t> bytes;
			const char *sval = val.c_str();
			unsigned int len = val.size();
			bytes.resize(len);
			copy(sval, sval+len, bytes.begin());
			PacketReader pr(bytes);
			// rec=(struct tinyrecord *) val.c_str();
			cerr<<"in get: got value ["<<makeHexDump(val)<<"]"<<endl;
			valtype = QType(pr.get16BitInt());
			cerr<<"value has qtype "<<valtype.getName()<<endl;
			cerr<<"query has qtype "<<d_qtype.getName()<<endl;
			char locwild = pr.get8BitInt();
			if(locwild != '\075')
				goto next;
			if(d_qtype.getCode()==QType::ANY || valtype==d_qtype)
			{
				cerr<<"WE GOT HIM"<<endl;

				rr.qtype = valtype;
				rr.qname = d_qdomain;
				rr.ttl = pr.get32BitInt();

				uint64_t timestamp = (pr.get32BitInt() << 32) + pr.get32BitInt();
				if(timestamp)
					goto next;

				cerr<<"passing to mastermake ["<<makeHexDump(sval)<<"]"<<endl;

				DNSRecord dr;
				dr.d_class = 1;
				dr.d_type = valtype.getCode();
				dr.d_clen = val.size()-pr.d_pos;
				DNSRecordContent *drc = DNSRecordContent::mastermake(dr, pr);

				string content = drc->getZoneRepresentation();
	            if(rr.qtype.getCode() == QType::MX || rr.qtype.getCode() == QType::SRV)
	            {
					vector<string>parts;
					stringtok(parts,content," ");
					rr.priority=atoi(parts[0].c_str());
					rr.content=content.substr(parts[0].size()+1);
	            }
	            else
	            {
					rr.content = content;
	            }
				cerr<<"rr.priority: "<<rr.priority<<", rr.content: ["<<rr.content<<"]"<<endl;
			}
			return true;
	}
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
