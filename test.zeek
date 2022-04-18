@load base/frameworks/sumstats

event http_reply(c: connection, version: string, code: count, reason: string)
{
  # count of all response
	SumStats::observe("count_of_all_resp", 
      SumStats::Key($host = c$id$orig_h), 
      SumStats::Observation($num = 1));
	if (code == 404){
		  # count of 404 response
      SumStats::observe("count_of_404_resp", 
          SumStats::Key($host = c$id$orig_h), 
          SumStats::Observation($num = 1));
      #  count of 404 url response
      SumStats::observe("count_of_url_404_resp", 
          SumStats::Key($host = c$id$orig_h), 
          SumStats::Observation($str = c$http$host + c$http$uri));
    	}
}
    
event zeek_init()
{
	local r1 = SumStats::Reducer($stream="count_of_all_resp", $apply=set(SumStats::SUM));
	local r2 = SumStats::Reducer($stream="count_of_404_resp", $apply=set(SumStats::SUM));
	local r3 = SumStats::Reducer($stream="count_of_url_404_resp", $apply=set(SumStats::UNIQUE));

  SumStats::create([$name = "scanner",
      $epoch = 10mins,
      $reducers = set(r1, r2, r3),
      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
      {
          if("count_of_all_resp" in result && "count_of_404_resp" in result && "count_of_url_404_resp" in result)
          {
              local a = result["count_of_all_resp"]$sum;
              local b = result["count_of_404_resp"]$sum;
              local c = result["count_of_url_404_resp"]$unique;
              if(a > 2 && b > 0.2 * a && c > 0.5 * b){
                  print fmt("%s is a scanner with %d scan attemps on %d urls", key$host, b, c);
              }
          }
      }
 ]);
}
