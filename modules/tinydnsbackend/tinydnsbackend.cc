#include "tinydnsbackend.hh"
#include <cdb.h>
#include <pdns/dnslabel.hh>
#include <pdns/misc.hh>
#include <pdns/dnsrecords.hh>
#include <boost/foreach.hpp>

const string backendname="[TinyDNSBackend]";
vector<string> CDB::findall(const string &key)
{
	vector<string> ret;
	struct cdb cdb;
	struct cdb_find cdbf; /* structure to hold current find position */

	int fd = open(d_cdbfile.c_str(), O_RDONLY);
	if (fd < 0)
	{
		L<<Logger::Error<<backendname<<" Failed to open cdb database file '"<<d_cdbfile<<"'. Error: "<<stringerror()<<endl;
		throw new AhuException(backendname + " Failed to open cdb database file '"+d_cdbfile+"'. Error: " + stringerror());
	}

	int cdbinit = cdb_init(&cdb, fd);
	if (cdbinit < 0) 
	{
		L<<Logger::Error<<backendname<<" Failed to initialize cdb database. ErrorNr: '"<<cdbinit<<endl;
		throw new AhuException(backendname + " Failed to initialize cdb database.");
	}
	fprintf(stderr, "[findall] key [%s] length [%lu]\n", key.c_str(), key.size());
	cerr<<"[findall] doing cdb lookup of key ["<<makeHexDump(key)<<"]"<<endl;

	cdb_findinit(&cdbf, &cdb, key.c_str(), key.size());
	int x=0;
	while(cdb_findnext(&cdbf) > 0) {
		x++;
		unsigned int vpos = cdb_datapos(&cdb);
		unsigned int vlen = cdb_datalen(&cdb);
		char *val = (char *)malloc(vlen);
		cdb_read(&cdb, val, vlen, vpos);
		string sval(val, vlen);
		// cerr<<"got value ["<<makeHexDump(sval)<<"]"<<endl;
		ret.push_back(sval);
		free(val);
	}
	fprintf(stderr, "[findall] Found [%d] records for key [%s]\n", x, key.c_str());
	close(fd);
	return ret;
}




TinyDNSBackend::TinyDNSBackend(const string &suffix)
{
	setArgPrefix("tinydns"+suffix);
	d_cdb=new CDB(getArg("dbfile"));
	
	//TODO: Make constant or define? 
	d_taiepock = 4611686018427387904ULL;
}

bool TinyDNSBackend::list(const string &target, int domain_id)
{
	return false;
}

void TinyDNSBackend::lookup(const QType &qtype, const string &qdomain, DNSPacket *pkt_p, int zoneId)
{
	DNSLabel l(qdomain.c_str());
	string key=l.binary();

	L<<Logger::Debug<<"[lookup] query for qtype ["<<qtype.getName()<<"] qdomain ["<<qdomain<<"]"<<endl;
	L<<Logger::Debug<<"[lookup] key ["<<makeHexDump(key)<<"]"<<endl;
	d_qtype=qtype;
	d_values=d_cdb->findall(key);
	d_qdomain = qdomain;
}

bool TinyDNSBackend::get(DNSResourceRecord &rr)
{
	L<<Logger::Debug<<"[GET]"<<endl;

	//TODO: Labels aren't very nice. Maybe find another way of doing this?
	next:
		if(!d_values.size())
		{
			cerr<<"Returning false..."<<endl;
			return false;
		}
		else
		{
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
			cerr<<"in get: got value ["<<makeHexDump(val)<<"]" <<endl;
			valtype = QType(pr.get16BitInt());
			cerr<<"value has qtype "<<valtype.getName()<<endl;
			cerr<<"query has qtype "<<d_qtype.getName()<<endl;
			char locwild = pr.get8BitInt();
			if(locwild != '\075') 
			{
			 	// TODO: wildcards; 
				// TODO: locations
				cerr<<"wildcard char, or location"<<endl;
				goto next;
			}
			if(d_qtype.getCode()==QType::ANY || valtype==d_qtype)
			{
				cerr<<"WE GOT HIM"<<endl;

				rr.qtype = valtype;
				rr.qname = d_qdomain;
				rr.ttl = pr.get32BitInt();


				uint64_t timestamp = pr.get32BitInt();
				timestamp <<= 32;
				timestamp += pr.get32BitInt();
				if(timestamp) 
				{
					uint64_t now = d_taiepock + time(NULL);
					cerr<<"TIMESTAMP:"<<timestamp<<endl;
					cerr<<"      NOW:"<<now<<endl;
					uint32_t diff = timestamp - now;
					cerr<<"     DIFF:"<< diff<<endl;
					if (timestamp < now)
					{
						cerr<<"Record is old, do not return."<<endl;
						goto next;
					}
					if (rr.ttl == 0)
					{
						rr.ttl = timestamp - now;
					}
				}

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
			cerr<<"Returning true..."<<endl;
			return true;
		}
}

// boilerplate
class TinyDNSFactory: public BackendFactory
{
public:
	TinyDNSFactory() : BackendFactory("tinydns") {}

	void declareArguments(const string &suffix="")
	{
		declare(suffix, "dbfile", "Location of the cdb data file", "data.cdb");
	}


	DNSBackend *make(const string &suffix="")
	{
		return new TinyDNSBackend(suffix);
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
