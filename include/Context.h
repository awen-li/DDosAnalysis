/***********************************************************
 * Author: Wen Li
 * Date  : 11/13/2019
 * Describe: Context for flow analysis
 * History:
   <1> 11/13/2019 , create
************************************************************/

#ifndef _CONTEXT_H_
#define _CONTEXT_H_
#include <BasicType.h>
#include <Log.h>
#include <Packet.h>


using namespace std;


class Bucket
{
private:
    DWORD m_Capacity;
    DWORD m_Left;
    DWORD m_Rate;
    DWORD m_TimeStamp;

public:
    Bucket (DWORD Capacity, DWORD Rate)
    {
        SetAttr (Capacity, Rate);
    }

    VOID SetAttr (DWORD Capacity, DWORD Rate)
    {
        m_Capacity  = Capacity;
        m_Left      = Capacity;
        m_Rate      = Rate;
        m_TimeStamp = CLOCK_IN_SEC();

        return;
    }

    inline DWORD Grant ()
    {
        DWORD Now = CLOCK_IN_SEC();
        
        m_Left += (Now - m_TimeStamp) * m_Rate;
        if (m_Left > m_Capacity)
        {
            m_Left = m_Capacity;
        }

        m_TimeStamp = Now;

        if (m_Left <= 0)
        {
            return 0;
        }
        else
        {
            return (--m_Left);
        }
    }
    
};

class User
{
private:
    ULONG m_SrcMac;
    WORD m_EthType;

    DWORD m_TimeStamp;

    DWORD m_PacketsNum;

    DWORD m_AnlyResult;

    Bucket *m_Bucket;

public:
    User (ULONG SrcMac, WORD EthType)
    {
        m_SrcMac  = SrcMac;
        m_EthType = EthType;
        m_PacketsNum = 0;

        m_Bucket = new Bucket(128 * 4, 128);
        assert (m_Bucket != NULL);

        m_TimeStamp = CLOCK_IN_SEC ();

        m_AnlyResult = 0;
    }

    inline Bucket* GetBucket ()
    {
        return m_Bucket;
    }

    inline VOID IncreasePkts ()
    {
        m_PacketsNum++;
    }

    inline DWORD GetPktsRate ()
    {
        DWORD Int = CLOCK_IN_SEC () - m_TimeStamp;

        if (Int)
        {
            return m_PacketsNum/Int;
        }
        else
        {
            return 0;
        }
    }

    inline VOID SetBucket (DWORD Capacity, DWORD Rate)
    {
        m_Bucket->SetAttr (Capacity, Rate);
        return;
    }

    inline DWORD GetAnlyResult ()
    {
        return m_AnlyResult;
    }

    inline VOID  SetAnlyResult (DWORD AnlyResult)
    {
        m_AnlyResult = AnlyResult;
    }

    inline ULONG GetMac ()
    {
        return m_SrcMac;
    }

    inline WORD GetEthType ()
    {
        return m_EthType;
    }

    typedef struct 
    {
        bool operator()(User* L, User* R) 
        {
            if (L->GetEthType() != R->GetEthType())
            {
                return (L->GetEthType() < R->GetEthType());
            }
            else if (L->GetMac() != R->GetMac())
            {
                return (L->GetMac() < R->GetMac());
            }
            else
            {
                return 0;
            }
        }
    } EqualUser;
};

typedef std::set<User*, typename User::EqualUser> T_UsetSet;

class UserCtl
{
private:
    static T_UsetSet *m_UserSet;

public:
    UserCtl ()
    {
        if (m_UserSet == NULL)
        {
            m_UserSet = new T_UsetSet;
            assert (m_UserSet != NULL);
        }
    }

    VOID Release ()
    {
        if (m_UserSet != NULL)
        {
            delete m_UserSet;
            m_UserSet = NULL;
        }
        
    }

    User *Query(ULONG SrcMac, WORD EthType);
    User *Add(ULONG SrcMac, WORD EthType);
    VOID Delete(ULONG SrcMac, WORD EthType);

    inline static T_UsetSet::iterator begin()
    {
        return m_UserSet->begin();
    }

    inline static T_UsetSet::iterator end()
    {
        return m_UserSet->end();
    }

    inline static DWORD GetUserNum ()
    {
        if (m_UserSet == NULL)
        {
            return 0;
        }
        
        return m_UserSet->size();
    }
};


#endif 
