import string

from matplotlib.pylab import rand, randint
from main import go_main

def find_good_charper(text, end_idx):
    start_idx = end_idx
    while good_char_condition(text[start_idx]):
        start_idx-=1
    result = text[start_idx+1:end_idx+1]
    if len(result) > 20:
        result = result[-20:]
    return result

def find_good_charper_to_insert(text, start_idx):
    end_idx = start_idx
    print(text[end_idx])
    while end_idx < len(text) and good_char_condition(text[end_idx]):
        print(text[end_idx])
        end_idx+=1
    return text[start_idx:min(end_idx, start_idx+20)]

def good_char_condition(c):
    return c in "abcdefghigklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" + " .,;:!?"



with open("refer1.txt", "r", encoding='utf-8') as f_refer1:
    refer_text1 = f_refer1.read()
    refer_text1 = refer_text1.replace("\n", " ")
    refer_text1 = refer_text1.replace("  ", " ")
with open("refer2.txt", "r", encoding='utf-8') as f_refer2:
    refer_text2 = f_refer2.read()
    refer_text2 = refer_text2.replace("\n", " ")
    refer_text2 = refer_text2.replace("  ", " ")
with open("refer3.txt", "r", encoding='utf-8') as f_refer3:
    refer_text3 = f_refer3.read()
    refer_text3 = refer_text3.replace("\n", " ")
    refer_text3 = refer_text3.replace("  ", " ")
    refer_text3 = refer_text3.replace("'", "")

last_text_idx = -1
for i in range(200):

    with open("plaintexts_guess copy.txt", encoding='cp1251') as f:
        content = f.readlines()

    if len(content) > 20:
        exit()
    text1 = content[1].rstrip('\n')
    text2 = content[8].rstrip('\n')
    text3 = content[15].rstrip('\n')

    current_idx1 = text1.find("__")
    current_idx2 = text2.find("__")
    current_idx3 = text3.find("__")

    print(f"First '_' in P1 at {current_idx1}, P2 at {current_idx2}, P3 at {current_idx3}")
    max_idx = max(current_idx1, current_idx2, current_idx3)
    current_idx1 = max_idx - 1
    current_idx2 = max_idx - 1
    current_idx3 = max_idx - 1
    
    cycle_num = (i + 2) % 3
    
    
    if cycle_num == 0:
        if not good_char_condition(text1[current_idx1]) or last_text_idx == 1:
            continue
        last_text_idx = 1
        good_charper = find_good_charper(text1, current_idx1)
        refer_idx1 = refer_text1.find(good_charper)
        if refer_idx1 == -1 or len(good_charper) < 5:
            continue
        refer_idx1 += len(good_charper)
        charper_to_insert = find_good_charper_to_insert(refer_text1, refer_idx1)
        text1_list = list(text1)
        for c in charper_to_insert:
            text1_list[current_idx1 + 1] = c
            current_idx1+=1
        text1 = ''.join(text1_list)
        content[1] = text1
        with open("plaintexts_guess copy.txt", "w") as f:
            f.writelines(content)
        print(f"Inserted '{charper_to_insert}' into P1 at position {current_idx1 - len(charper_to_insert) + 1}..{current_idx1}")
    elif cycle_num == 1:
        if not good_char_condition(text2[current_idx2]) or last_text_idx == 2:
            continue
        last_text_idx = 2
        good_charper = find_good_charper(text2, current_idx2)
        refer_idx2 = refer_text2.find(good_charper)
        if refer_idx2 == -1 or len(good_charper) < 5:
            continue
        refer_idx2 += len(good_charper)
        charper_to_insert = find_good_charper_to_insert(refer_text2, refer_idx2)
        text2_list = list(text2)
        for c in charper_to_insert:
            text2_list[current_idx2 + 1] = c
            current_idx2+=1
        text2 = ''.join(text2_list)
        content[8] = text2
        with open("plaintexts_guess copy.txt", "w") as f:
            f.writelines(content)
        print(f"Inserted '{charper_to_insert}' into P2 at position {current_idx2 - len(charper_to_insert) + 1}..{current_idx2}")
    else:
        if not good_char_condition(text3[current_idx3]) or last_text_idx == 3:
            continue
        last_text_idx = 3
        good_charper = find_good_charper(text3, current_idx3)
        refer_idx3 = refer_text3.find(good_charper)
        if refer_idx3 == -1 or len(good_charper) < 5:
            continue
        refer_idx3 += len(good_charper)
        charper_to_insert = find_good_charper_to_insert(refer_text3, refer_idx3)
        text3_list = list(text3)
        for c in charper_to_insert:
            text3_list[current_idx3 + 1] = c
            current_idx3+=1
        text3 = ''.join(text3_list)
        content[15] = text3
        with open("plaintexts_guess copy.txt", "w") as f:
            f.writelines(content)
        print(f"Inserted '{charper_to_insert}' into P3 at position {current_idx3 - len(charper_to_insert) + 1}..{current_idx3}")
    
    go_main()


    




    
