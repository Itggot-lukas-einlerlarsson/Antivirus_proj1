#include "../include/Antivirus.hpp"


std::vector<std::string> Antivirus::search_files(std::string directory) //deepfirst
//finner alla filer vi ska kontrollera signaturer med.
{
  std::vector<std::string> subdirs;
  std::vector<std::string> paths;
  for (auto& file : std::experimental::filesystem::directory_iterator(directory))
  {
    paths.push_back(file.path());
  }
  for (std::string path : paths)
  {
    if (std::experimental::filesystem::is_directory(path))
    {
      std::vector<std::string> v = search_files(path); //recursive
      subdirs.insert(subdirs.end(), v.begin(), v.end());
    }
    if (std::experimental::filesystem::is_regular_file(path)) //skickar enbart in filer som ska kontrolleras i subdirs.
    {
      subdirs.push_back(path); //subdirs innehåller främst alla sökvägar men tillslut enbart filerna som ska kontrolleras.
    }
  }
  return subdirs;
}


std::vector<std::string> Antivirus::read_virus_files(std::string vfile)
//läser av signatures.db om den går att öppna.
{
  std::vector<std::string> virus_files;
  std::vector<std::string> file_names;
  std::ifstream virusfile(vfile, std::ios::in);
  if (virusfile.is_open())
  {
    std::string line;
    while (std::getline(virusfile, line))
    {
      virus_files.push_back(line);
    }
    virusfile.close();
  }
  else
  { //om filen ej kan öppnas/hittas.
    std::cerr << "Unable to open file: 'signatures.db'.\nPut 'signatures.db' in the same directory as 'program' to run.\n";
    exit(1);
  }
  return virus_files;
}


std::vector<std::string> Antivirus::hex_convert(std::vector<std::string> virus_files)
{
  std::vector<std::string> content; // innehåller alla signaturer i asciiform
  std::string signature; // ascii signatur behållares
  int temp_int; // temporär int som används vid konverteringen.
  std::string str; // temporär string som håller hexadecimalabyten.
  std::size_t pos; // positionen där hexadecimala signaturen börjar.
  for(std::string hex_signature : virus_files)
  {
    pos = hex_signature.find("=");
    signature = "";
    for (int i = pos+1; i < hex_signature.length(); i+=2)
    {
      temp_int = 0;
      str.push_back(hex_signature[i]);
      str.push_back(hex_signature[i+1]);
      for (int j = 0, t = 1; j < 2; j++, t--)
      {
        if (str[j]>='0' && str[j]<='9')
        {
            temp_int += (str[j] - 48)*pow(16,t); 
        }
        if(str[j]>='a' && str[j]<='f')
        {
          if (str[j] == 'a')
          {
            temp_int += 10*pow(16,t);
          }
          if (str[j] == 'b')
          {
            temp_int += 11*pow(16,t);
          }
          if (str[j] == 'c')
          {
            temp_int += 12*pow(16,t);
          }
          if (str[j] == 'd')
          {
            temp_int += 13*pow(16,t);
          }
          if (str[j] == 'e')
          {
            temp_int += 14*pow(16,t);
          }
          if (str[j] == 'f')
          {
            temp_int += 15*pow(16,t);
          }
        }
      }
      signature += char(temp_int);
      str = "";
    }
    content.push_back(signature);
  }
  return content;
}


std::vector<std::string> Antivirus::check_signatures(std::vector<std::string> signatures,std::vector<std::string> search_files, std::vector<std::string> virus_files)
//går igenom vectorn med alla virussignaturer och läser av virusfilerna och kollar om någon signatur matchar.
//returnerar sträng med matchningsresultat.
{
  //return value - behållare av ala matchningar.
  std::vector<std::string> matched_files;

  //mängden karaktärer som ska läsas i alla filer som läses.
  int signature_length;

  //behålleare för vad som läses under checkningen.
  char c;
  std::string data;
  std::string line;

  //håller positionen av virusfilens ´=´ tecken
  int pos;

  //räknare under fillsning
  int count;
  for (int i = 0; i < signatures.size(); i++)
  {
    signature_length = signatures[i].length();
    for (std::string search_file : search_files)
    {
      data = "";
      count = 0;
      std::ifstream file(search_file,std::ios::in);
      while (file.get(c)) //sålänge det finns karaktärer att läsa
      {
        if (count < signature_length)
        {
          data.push_back(c);
          count++;
        }
        else
          break; //avslutar loopen när vi tagit tillräckligt med data
      }
      if (data == signatures[i]) //kollar om datan är likadan som virussignaturen
      {
        pos = virus_files[i].find("=");
        matched_files.push_back(search_file + " is " + virus_files[i].substr(0,pos));
      }
    }
  }
  return matched_files;
}



void Antivirus::logfile_send(std::vector<std::string> matched_signatures)
//denna funktion skickar iväg signaturerna i en loggfil.
{
  //index för loop av vector
  int i = 0;

  std::ofstream outfile("AV.log", std::ios::out);
  if (outfile.is_open())
  {
    outfile << "virusfiles in given directory:" << '\n';
    while (i < matched_signatures.size())
    {
      outfile << "Virusfile " << i << ':' <<matched_signatures[i] << '\n';
      i++;
    }
    outfile.close();
  }
}
