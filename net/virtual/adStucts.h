struct sockaddr_ad {
         struct sa_family_t     ad_family;
         struct totaldaddr_t*    ad_bdaddr;
};


struct totaldaddr_t{
	struct sockaddr_rc bt;
	struct sockaddr_in inet;
};
