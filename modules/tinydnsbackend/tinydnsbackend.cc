#include "tinydnsbackend.hh"
#include <cdb.h>
#include <pdns/dnslabel.hh>
#include <pdns/misc.hh>
#include <pdns/iputils.hh>
#include <pdns/dnspacket.hh>
#include <pdns/dnsrecords.hh>
#include <utility>

const string backendname="[TinyDNSBackend]";

vector<string> TinyDNSBackend::getLocations()
{
	vector<string> ret;

	if (! d_dnspacket) {
		return ret;
	}

	//TODO: We do not have IPv6 support.
	if (d_dnspacket->getRealRemote().getBits() != 32) {
		return ret;
	}
	
	Netmask remote = d_dnspacket->getRealRemote();
	unsigned long addr = remote.getNetwork().sin4.sin_addr.s_addr;	

	char remoteAddr[4];
	remoteAddr[0] = (addr      )&0xff;
	remoteAddr[1] = (addr >>  8)&0xff;
	remoteAddr[2] = (addr >> 16)&0xff;
	remoteAddr[3] = (addr >> 24)&0xff;

	for (int i=4;i>=0;i--) {
		char *key = (char *)malloc(i+2);
		strncpy(key, remoteAddr, i);
		memmove(key+2, key, i);
		key[0]='\000';
		key[1]='\045';
		string searchkey(key, i+2);
		ret = d_cdbReader->findall(searchkey);
		free(key);

		//Biggest item wins, so when we find something, we can jump out.
		if (ret.size() > 0) {
			break;
		}
	}

	return ret; 
}

//TODO: call destructor on d_cdb
TinyDNSBackend::TinyDNSBackend(const string &suffix)
{
	setArgPrefix("tinydns"+suffix);
	d_cdbReader=new CDB(getArg("dbfile"));
	d_taiepoch = 4611686018427387904ULL + getArgAsNum("tai-adjust");
}

bool TinyDNSBackend::list(const string &target, int domain_id)
{
	d_isAxfr=true;
	DNSLabel l(target.c_str());
	string key = l.binary();
	bool x = d_cdbReader->searchSuffix(key);
	return x;
}

void TinyDNSBackend::lookup(const QType &qtype, const string &qdomain, DNSPacket *pkt_p, int zoneId)
{
	d_isAxfr = false;
	string queryDomain(qdomain.c_str(), qdomain.size());
	transform(queryDomain.begin(), queryDomain.end(), queryDomain.begin(), ::tolower);

	DNSLabel l(queryDomain.c_str());
	string key=l.binary();

	L<<Logger::Debug<<"[lookup] query for qtype ["<<qtype.getName()<<"] qdomain ["<<qdomain<<"]"<<endl;
	L<<Logger::Debug<<"[lookup] key ["<<makeHexDump(key)<<"]"<<endl;

	d_isWildcardQuery = false;
	if (key[0] == '\001' && key[1] == '\052') {
		d_isWildcardQuery = true;
		key.erase(0,2);
	}

	d_qtype=qtype;
	d_cdbReader->searchKey(key);
	d_dnspacket = pkt_p;
}

bool TinyDNSBackend::get(DNSResourceRecord &rr)
{
	L<<Logger::Debug<<"[GET] called"<<endl;
	pair<string, string> record;

	while (d_cdbReader->readNext(record)) {
		string val = record.second; 
		string key = record.first;

		cerr<<"GOT KEY: "<<makeHexDump(key)<<endl;
		cerr<<"GOT VAL: "<<makeHexDump(val)<<endl;

		//TODO: check if this is correct, what to do with wildcard records in an AXFR?
		if (!d_isAxfr) {
			// If we have a wildcard query, but the record we got is not a wildcard, we skip.
			if (d_isWildcardQuery && val[2] != '\052' && val[2] != '\053') {
				continue;
			}

			// If it is NOT a wildcard query, but we do find a wildcard record, we skip it.	
			if (!d_isWildcardQuery && (val[2] == '\052' || val[2] == '\053')) {
				continue;
			}
		}
		

		QType valtype;
		vector<uint8_t> bytes;
		const char *sval = val.c_str();
		unsigned int len = val.size();
		bytes.resize(len);
		copy(sval, sval+len, bytes.begin());
		PacketReader pr(bytes);
		valtype = QType(pr.get16BitInt());
		L<<Logger::Debug<<"[GET] ValType:"<<valtype.getName()<<endl;
		L<<Logger::Debug<<"[GET] QType:"<<d_qtype.getName()<<endl;
		char locwild = pr.get8BitInt();

		if(locwild != '\075' && (locwild == '\076' || locwild == '\053')) 
		{
			char recloc[2];
			recloc[0] = pr.get8BitInt();
			recloc[1] = pr.get8BitInt();	
			
			bool foundLocation = false;
			// IF the dnspacket is not set, we simply do not output any queries with a location.
			vector<string> locations = getLocations();
			while(locations.size() > 0) {
				string locId = locations.back();
				locations.pop_back();

				if (recloc[0] == locId[0] && recloc[1] == locId[1]) {
					foundLocation = true;
					break;
				}
			}
			if (!foundLocation) {
				continue;
			} 
		}
		if(d_qtype.getCode()==QType::ANY || valtype==d_qtype || d_isAxfr)
		{
			DNSLabel dnsKey(key.c_str(), key.size());
			rr.qname = dnsKey.human();
			rr.qtype = valtype;
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
						continue;
					}
					rr.ttl = timestamp - now; 
				}
				else if (now <= timestamp)
				{
					continue;
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
				cerr<<"Content:"<<content<<endl;
				cerr<<"Content:"<<makeHexDump(content)<<endl;
				vector<string>parts;
				stringtok(parts,content," ");
				rr.priority=atoi(parts[0].c_str());
				rr.content=content.substr(parts[0].size()+1);
			}
			else
			{
				rr.content = content;
			}
			cerr<<"Returning content: "<<rr.content<<endl;
			return true;
		}
	} // end of while
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
		declare(suffix, "tai-adjust", "This adjusts the TAI value if timestamps are used. These seconds will be added to the start point (1970) and will allow you to ajust for leap seconds. The default is 10.", "10");
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
