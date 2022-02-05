#ifndef ANTIVIRUS_HPP
#define ANTIVIRUS_HPP

#include <vector>
#include <string>
#include <fstream>
#include <iostream>
#include <experimental/filesystem>
#include <cmath>

struct Antivirus
{
  std::vector<std::string> search_files(std::string); //ger Alla filer från den dir man ger som argument
  std::vector<std::string> read_virus_files(std::string); //läser av signatures.db
  std::vector<std::string> hex_convert(std::vector<std::string>);
  std::vector<std::string> check_signatures(std::vector<std::string>,std::vector<std::string>, std::vector<std::string>); //går igenom vectorn med alla signaturer och läser av virusfilerna och kollar om någon signatur matchar.
  void logfile_send(std::vector<std::string> matched_signatures); //denna tar matchningarna som uppstod i check_signature och skickar i en ouputfil i exekverings katalogen
};

#endif //end ANTIVIRUS_HPP
