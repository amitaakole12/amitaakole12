
import math


def generate_alphabet(c1, c2):
  """Generates an alphabet from `c1` to `c2`, inclusive."""
  alphabet = str()
  for c in range(ord(c1), ord(c2)+1):
    yield chr(c)


def ff31_alpha_helper(c1 , c2,logger, other=None,plaintext=None, version='0.0.1'):
  alphabet_as_list = list(generate_alphabet(c1, c2))
  if other:
    for c in other:
      if c not in alphabet_as_list:
        alphabet_as_list.append(c)
  alphabet = ''.join(alphabet_as_list)
  length_alphabet = len(alphabet)
  length_input_max = 25
  #2 * math.floor(math.log(math.pow(2, 96), length_alphabet))
  logger.info("Alphabet has {} characters:".format(length_alphabet))
  logger.info("------------------------------------------------------------------------")
  logger.info(alphabet)
  logger.info("------------------------------------------------------------------------")
  logger.info("Maximum length of plain text to encode is {}".format(length_input_max))

  if plaintext:
    plaintext_chunks = []
    plaintext_is_valid = True
    for c in plaintext:
      if c not in alphabet_as_list:
        print("\"{}\" in plaintext value not found in list.".format(c))
        plaintext_is_valid = False
    length_plaintext = len(plaintext)
    if length_plaintext >= 2 and math.pow(length_alphabet,
                                          length_plaintext) >= 1000000 and length_plaintext <= length_input_max:
      plaintext_length_is_valid = True
    else:
      plaintext_length_is_valid = False
    if length_plaintext > length_input_max:
      for i in range(0, length_plaintext, length_input_max):
        plaintext_chunks.append(plaintext[i: i + length_input_max])
    logger.info("Plain text sample length is {}".format(length_plaintext))
    logger.info("Plain text sample provided is \"{}\"".format(plaintext))
    logger.info("Plain text sample contains valid characters: {}".format(plaintext_is_valid))
    logger.info("Plain text sample length is valid: {}".format(plaintext_length_is_valid))
    if len(plaintext_chunks):
      logger.info("Split the plain text sample for encoding as follows:")
      for chunk in plaintext_chunks:
        logger.info("  \"{}\"".format(chunk))





#ff31_alpha_helper(c1="0" , c2="z", other=" ",plaintext="Yash Khemani", version='0.0.1')






