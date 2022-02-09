#include "include/Antivirus.hpp"

int main(int argc, char const *argv[])
{
  //checking if too many arguments are used when executing program:
  if (argc != 2)
  {
    std::cerr << "Two arguments is enough. example: ./programname /your/input/directory/" << '\n' << "'make run' should also work." << std::endl;
    exit(1);
  }

  std::string input = argv[1];
  Antivirus proj1_struct;

  std::vector<std::string> searched_files = proj1_struct.search_files(input);
  std::vector<std::string> virus_files = proj1_struct.read_virus_files("signatures.db");
  std::vector<std::string> converted_signatures = proj1_struct.hex_convert(virus_files);
  std::vector<std::string> matched_signatures = proj1_struct.check_signatures(converted_signatures,searched_files, virus_files);
  proj1_struct.logfile_send(matched_signatures);

  std::cout << "Virussearch done.\n-> AV.log created in directory where program was run." << '\n';
  return 0;
}
