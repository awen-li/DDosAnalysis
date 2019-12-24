#include "goose_receiver.h"
#include "goose_subscriber.h"
#include "hal_thread.h"
#include "mms_value.h"
#include "goose_publisher.h"

#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>

static int running=1;
FILE *out,*in;

void sigint_handler(int signalId)
{
    running = 0;
}

void gooseListener(GooseSubscriber subscriber, void* parameter)
{
    //printf("GOOSE event:\n");
    //printf("  stNum: %u sqNum: %u\n", GooseSubscriber_getStNum(subscriber),GooseSubscriber_getSqNum(subscriber));
    //printf("  timeToLive: %u\n", GooseSubscriber_getTimeAllowedToLive(subscriber));

    uint64_t timestamp = GooseSubscriber_getTimestamp(subscriber);

    //printf("  timestamp: %u.%u\n", (uint32_t) (timestamp / 1000), (uint32_t) (timestamp % 1000));

    MmsValue* values = GooseSubscriber_getDataSetValues(subscriber);

    char buffer[1024];

    MmsValue_printToBuffer(values, buffer, 1024);
    char des[32];
    char ret[32];
    for(int i=1;i<strlen(buffer);i++)
    {
	if(buffer[i]==',')
	{
	    strcpy(des,&buffer[1]);
	    des[i-1]=0;
	    strcpy(ret,&buffer[i+1]);
	    break;
	}
    }
    ret[strlen(ret)-1]=0;
    //printf("%s\n",des);
    if(strcmp(des,"ied1")==0)
    {
	int retx=atoi(ret);
        struct timeval timex;
        struct timezone tz;
        gettimeofday(&timex,&tz);
        int now=(timex.tv_sec%1000)*1000000+timex.tv_usec;
        if(now-retx<5000&&now>retx){
            fprintf(in,"%d %d %d\n",retx,now,now-retx);
        }
    }
}



int main(int argc, char *argv[])
{

	in=fopen("in.txt","w");
	out=fopen("out.txt","w");
	char interface[32]="ied1-eth0";

	printf("Using interface %s\n", interface);

	CommParameters gooseCommParameters;

	gooseCommParameters.appId = 1000;
	gooseCommParameters.dstAddress[0] = 0x01;
	gooseCommParameters.dstAddress[1] = 0x0c;
	gooseCommParameters.dstAddress[2] = 0xcd;
	gooseCommParameters.dstAddress[3] = 0x01;
	gooseCommParameters.dstAddress[4] = 0x00;
	gooseCommParameters.dstAddress[5] = 0x01;
	gooseCommParameters.vlanId = 0;
	gooseCommParameters.vlanPriority = 4;

	/*
	 * Create a new GOOSE publisher instance. As the second parameter the interface
	 * name can be provided (e.g. "eth0" on a Linux system). If the second parameter
	 * is NULL the interface name as defined with CONFIG_ETHERNET_INTERFACE_ID in
	 * stack_config.h is used.
	 */
	GoosePublisher publisher = GoosePublisher_create(&gooseCommParameters, interface);
  int pid = fork();
	if(pid){
	if (publisher) {
	    GoosePublisher_setGoCbRef(publisher, "simpleIOGenericIO/LLN0$GO$gcbAnalogValues");
	    GoosePublisher_setConfRev(publisher, 1);
	    GoosePublisher_setDataSetRef(publisher, "simpleIOGenericIO/LLN0$AnalogValues");

	    int i = 0;

	    for (i = 0; i<600; i++) {
	        Thread_sleep(100);
	  	struct timeval timex;
          	struct timezone tz;
          	char num[32];
	  	gettimeofday(&timex,&tz);
	  	int now=(timex.tv_sec%1000)*1000000+timex.tv_usec;
          	LinkedList dataSetValues = LinkedList_create();
	  	LinkedList_add(dataSetValues, MmsValue_newVisibleString("ied2"));
	  	sprintf(num,"%d",now);
          	LinkedList_add(dataSetValues, MmsValue_newVisibleString(num));
		fprintf(out,"%d\n",now);
          //LinkedList_add(dataSetValues, "Hello World");
          //LinkedList_add(dataSetValues, MmsValue_newBinaryTime(true));
          	//LinkedList_add(dataSetValues, MmsValue_newIntegerFromInt32(5678));
	        if (GoosePublisher_publish(publisher, dataSetValues) == -1) {
	            printf("Error sending message!\n");
	        }
					LinkedList_destroyDeep(dataSetValues, (LinkedListValueDeleteFunction) MmsValue_delete);

	    }
	    GoosePublisher_destroy(publisher);
	}
  }
	else
	{
	  GooseReceiver receiver = GooseReceiver_create();

	  GooseReceiver_setInterfaceId(receiver, "ied1-eth0");

    GooseSubscriber subscriber = GooseSubscriber_create("simpleIOGenericIO/LLN0$GO$gcbAnalogValues", NULL);

    GooseSubscriber_setAppId(subscriber, 1000);

    GooseSubscriber_setListener(subscriber, gooseListener, NULL);

    GooseReceiver_addSubscriber(receiver, subscriber);

    GooseReceiver_start(receiver);
    time_t start,now;
    time(&start);
    if (GooseReceiver_isRunning(receiver)) {
        signal(SIGINT, sigint_handler);

        while (running) {
	    time(&now);
            if(now-start>65)
		break;
            Thread_sleep(1);
        }
    }
    else {
        printf("Failed to start GOOSE subscriber. Reason can be that the Ethernet interface doesn't exist or root permission are required.\n");
    }

    GooseReceiver_stop(receiver);

    GooseReceiver_destroy(receiver);

	}
	//LinkedList_destroyDeep(dataSetValues, (LinkedListValueDeleteFunction) MmsValue_delete);
}
