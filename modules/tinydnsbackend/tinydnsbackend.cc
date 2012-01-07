#include "tinydnsbackend.hh"
#include <cdb.h>
#include <pdns/dnslabel.hh>
#include <pdns/misc.hh>
#include <pdns/iputils.hh>
#include <pdns/dnspacket.hh>
#include <pdns/dnsrecords.hh>

#include <boost/foreach.hpp>
#include <boost/tokenizer.hpp>



const string backendname="[TinyDNSBackend]";
struct cdb CDB::initcdb(int &fd)
{
	struct cdb cdb;

	fd = open(d_cdbfile.c_str(), O_RDONLY);
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
	
	return cdb;
}


vector<string> CDB::findlocations(char &remote)
{
	vector<string> ret;
	int fd = -1;
	struct cdb cdb = initcdb(fd);
	struct cdb_find cdbf;

	for (int i=4;i>0;i--) {
		char *key = (char *)malloc(i+2);
		strncpy(key, &remote, i);
		memmove(key+2, key, i);
		key[0]=0x00;
		key[1]=0x25;
		
		cdb_findinit(&cdbf, &cdb, key, i+2);
		while(cdb_findnext(&cdbf) > 0) {
			char location[2];
			unsigned int vpos = cdb_datapos(&cdb);
			unsigned int vlen = cdb_datalen(&cdb);
			if(vlen != 2) {
				throw new AhuException("Found location, but data was not 2 chars. Check your CDB database!");
			}
			cdb_read(&cdb, location, vlen, vpos);
			string val(location, vlen);
			ret.push_back(val);
		}

		free(key);
	}

	close(fd);
	return ret;
}

vector<string> CDB::findall(const string &key)
{
	vector<string> ret;
	int fd;
	struct cdb cdb = initcdb(fd);
	struct cdb_find cdbf; /* structure to hold current find position */

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
	d_taiepoch = 4611686018427387904ULL;
}

bool TinyDNSBackend::list(const string &target, int domain_id)
{
	cerr<<"LIST CALLED!"<<endl;
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
	if (pkt_p) {
	
		//TODO: look at IpTOU32 or U32ToIP for a better way to do this.
		string ip = pkt_p->getRealRemote().toStringNoMask();
		
		boost::char_separator<char> sep(".");
		boost::tokenizer< boost::char_separator<char> > tokens(ip, sep);
		
		int i =0;
		BOOST_FOREACH(string t, tokens) 
		{
			d_remote[i] = (char)atoi(t.c_str());
			i++;
		}
	}
}

bool TinyDNSBackend::get(DNSResourceRecord &rr)
{
	L<<Logger::Debug<<"[GET]"<<endl;

	while (d_values.size()) 
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
		valtype = QType(pr.get16BitInt());
		char locwild = pr.get8BitInt();
		if(locwild != '\075') 
		{
			if (locwild == '>')
			{
				vector<string> locations = d_cdb->findlocations(*d_remote);
				char recloc[2];
				recloc[0] = pr.get8BitInt();
				recloc[1] = pr.get8BitInt();	
	
				bool foundLocation = false;
				while(locations.size() > 0) {
					string locId = locations.back();
					locations.pop_back();
					if (recloc[0] == locId[0] && recloc[1] == locId[1]) {
						foundLocation = true;
						break;
					}
				}

				if (!foundLocation) {
					cerr<<"The record has a location, and the remote does not match it. Skipping!"<<endl;
					continue;
				}
			} 
			else if (locwild == '*')
			{
				// Wildcard records replace \075 with \052 and \076 with \053; also, the owner name omits the wildcard.)
				cerr<<"Wildcard record"<<endl;
				continue;
			}
			else if (locwild == '+')
			{
				cerr<<"Location and a wildcard"<<endl;
				continue;
			}
		}
		if(d_qtype.getCode()==QType::ANY || valtype==d_qtype)
		{
			rr.qtype = valtype;
			rr.qname = d_qdomain;
			rr.ttl = pr.get32BitInt();

			uint64_t timestamp = pr.get32BitInt();
			timestamp <<= 32;
			timestamp += pr.get32BitInt();
			if(timestamp) 
			{
				uint64_t now = d_taiepoch + time(NULL);
				if (rr.ttl == 0)
				{
					if (timestamp < now)
					{
						cerr<<"Record is old, do not return."<<endl;
						continue;
					}
					rr.ttl = timestamp - now; 
				}
				else
				{
					if (now <= timestamp)
					{
						cerr<<"Record is not valid yet. Skipping."<<endl;
						continue;
					}
				}
			}

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
			cerr<<"Returning true..."<<endl;
			return true;
		}
	}
	cout <<"Loop done. return false"<<endl;
	return false;
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
