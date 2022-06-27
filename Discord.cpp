#include "Discord.h"
#include "chrono"

static int64_t eptime = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();

void Discord::Initialize()
{
    DiscordEventHandlers Handle;
    memset(&Handle, 0, sizeof(Handle));
    Discord_Initialize("977523042399965195", &Handle, 1, NULL);
}


//back up
void Discord::Update()
{
    DiscordRichPresence discordPresence;
    memset(&discordPresence, 0, sizeof(discordPresence));
    discordPresence.state = "Playing PUBGM 2.0 | Gameloop";
    discordPresence.details = "SNAKE PRIVATE BYPASS PUBGM | https://discord.gg/PUZM46ZPD5";
    std::time_t CurrentTime = std::time(0); discordPresence.startTimestamp = CurrentTime;    /*discordPresence.endTimestamp = 1507665886;*/
    discordPresence.largeImageKey = "imgonline-com-ua-resize-udkx9vdcjrhyfxj";
    discordPresence.largeImageKey = "snakesmall_1_";
    discordPresence.largeImageText = "SNAKE PRIVATE BYPASS";
    discordPresence.smallImageText = "Rogue - Level 100";
    discordPresence.partyId = "ae488379-351d-4a4f-ad32-2b9b01c91657";
    discordPresence.partySize = 1;
    discordPresence.partyMax = 4;
    discordPresence.joinSecret = "MTI4NzM0OjFpMmhuZToxMjMxMjM= ";
    Discord_UpdatePresence(&discordPresence);


 /*   DiscordRichPresence discordPresence;
    memset(&discordPresence, 0, sizeof(discordPresence));
    discordPresence.state = "Playing PUBGM 2.0 | Gameloop";
    discordPresence.details = "SNAKE PRIVATE BYPASS PUBGM | https://discord.gg/PUZM46ZPD5";
    discordPresence.startTimestamp = 1507665886;
    discordPresence.endTimestamp = 1507665886;
    discordPresence.largeImageKey = "snakesmall_1_";
    discordPresence.largeImageText = "SNAKE PRIVATE BYPASS";
    discordPresence.smallImageText = "Rogue - Level 100";
    discordPresence.partyId = "ae488379-351d-4a4f-ad32-2b9b01c91657";
    discordPresence.partySize = 1;
    discordPresence.partyMax = 5;
    discordPresence.joinSecret = "MTI4NzM0OjFpMmhuZToxMjMxMjM= ";
    Discord_UpdatePresence(&discordPresence);*/


}


