/***********************************************************
 * Author: Wen Li
 * Date  : 11/08/2019
 * Describe: dos attack analysis 
 * History:
   <1> 11/08/2019 , create
************************************************************/

#include "Capture.h"

VOID Help ()
{
    printf("************************************************\r\n");
    printf("*                help information              *\r\n");
    printf("************************************************\r\n");
    printf("-d device-name \r\n");
    printf("-t: training mode\r\n");
    printf("-a: analysis mode\r\n");
    printf("************************************************\r\n\r\n");

    return;
}


static VOID StartAsDaemon()
{
	pid_t pid;
	
	pid = fork();
	assert(pid != -1 && "fork fail");
	if(pid != 0)
	{
		exit(0);
	}
 
	assert(setsid() != -1 && "setsid fail");
	
	pid = fork();
	assert(pid != -1 && "fork fail");
	if(pid != 0)
	{
		exit(0);
	}
 
	close(0), close(1), close(2);
	umask(0);
	
	return;
}


static VOID GsAnalysis(BYTE *user,  struct pcap_pkthdr *Hdr, BYTE *PktData)
{
    if (Capture::GetEthType(PktData) == ETH_GOOSE)
    {
        AnlyWrap Anly;
        AnalysisCtl *AnlyCtl = Anly.GetAnalysisCtl ();
        assert (AnlyCtl != NULL);

        GsEthPacket Packet(PktData, Hdr->caplen);
        
        AnlyCtl->Run (&Packet);
    }
}

static VOID* FlowControl (VOID* Arg)
{
    UserCtl Uctl;

    while (true)
    {
        if (Uctl.GetUserNum() == 0)
        {
            sleep (20);
            continue;
        }

        for (auto Uit = Uctl.begin (); Uit != Uctl.end(); Uit++)
        {
            User *U = *Uit;

            if (U->GetAnlyResult () != RES_NULL)
            {
                ULONG SrcMac = U->GetMac ();
            }
        }
    }
    
    return NULL;
}



int main(int argc, char *argv[])
{
    string Device = "";
    DWORD RunMode = MODE_ANALYSIS;
    system("ovs-ofctl del-flows \"s1\"");
    system("ovs-ofctl add-flow \"s1\" \"action=normal\"");
    char ch;
    while((ch = getopt(argc, argv, "d:at")) != -1)
    {
        switch(ch)
        {
            case 'd':
            {
                Device = optarg;
                break;
            }
            case 'a':
            {
                RunMode = MODE_ANALYSIS;
                break;
            }
            case 't':
            {
                RunMode = MODE_TRAINING;
                break;
            }
            default:
            {
                Help ();
                return 0;
            }
        }
    }

    if (Device == "")
    {
        Help();
        return 0;
    }
    
	StartAsDaemon();
	
	DebugLog("Monitor is running\r\n");
    AnlyWrap Anly (RunMode);

    pthread_t Tid;
    DWORD Ret = pthread_create(&Tid, NULL, FlowControl, &Anly);
    assert (Ret == 0);
        
    Capture Cap(Device);
    Cap.CapturePacket ((pcap_handler)GsAnalysis);
	
	return 0;
}

