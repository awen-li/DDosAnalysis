/***********************************************************
 * Author: Wen Li
 * Date  : 11/08/2019
 * Describe: packet capture from interface
 * History:
   <1> 11/08/2019 , create
************************************************************/

#ifndef _CAPTURE_H_
#define _CAPTURE_H_
#include <BasicType.h>
#include <DosAnalysis.h>


using namespace std;

#define CAP_LEN  (2048)

class Capture
{
protected:
    string m_Device;
    DWORD  m_CapLen;
    pcap_t* m_CapHandle;

protected:
    BOOL IsDeviceOnline ();
    pcap_t* InitPcapHandle ();

    static void Analysis(BYTE *user,   struct pcap_pkthdr *Hdr, BYTE *PktData)
    {
    }

public:

    Capture (string Device)
    {
        m_Device = Device;
        assert (m_Device != "");

        m_CapLen = CAP_LEN;
        m_CapHandle = NULL;
    }
    
    VOID CapturePacket(pcap_handler Analysis);

    inline static WORD GetEthType (BYTE *PktData)
    {
        /* GOOSE:DstMac:01 0C CD 01 XX XX */
        if (PktData[0] == 0x01 && PktData[1] == 0x0c &&
            PktData[2] == 0xCD && (PktData[3] & GS_MASK))
        {
            return ETH_GOOSE;
        }

        return ETH_IPV4;
    }

    inline VOID CloseCapture ()
    {
        pcap_close(m_CapHandle);
        m_CapHandle = NULL;
    }
    
};


class IPCapture: public Capture
{
public:

    static void Analysis(BYTE *user,   struct pcap_pkthdr *Hdr, BYTE *PktData)
    {
        if (Capture::GetEthType(PktData) == ETH_GOOSE)
        {
            GsEthPacket Packet(PktData, Hdr->caplen);
        }
        else
        {
            IpEthPacket Packet(PktData, Hdr->caplen);
        }

        pcap_dump(user, Hdr, PktData);
    }


    IPCapture (string Device):Capture(Device)
    {
    }
    
};


#endif 
