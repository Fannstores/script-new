#!/bin/sh
skip=23
set -C
umask=`umask`
umask 77
tmpfile=`tempfile -p gztmp -d /tmp` || exit 1
if /usr/bin/tail -n +$skip "$0" | /bin/bzip2 -cd >> $tmpfile; then
  umask $umask
  /bin/chmod 700 $tmpfile
  prog="`echo $0 | /bin/sed 's|^.*/||'`"
  if /bin/ln -T $tmpfile "/tmp/$prog" 2>/dev/null; then
    trap '/bin/rm -f $tmpfile "/tmp/$prog"; exit $res' 0
    (/bin/sleep 5; /bin/rm -f $tmpfile "/tmp/$prog") 2>/dev/null &
    /tmp/"$prog" ${1+"$@"}; res=$?
  else
    trap '/bin/rm -f $tmpfile; exit $res' 0
    (/bin/sleep 5; /bin/rm -f $tmpfile) 2>/dev/null &
    $tmpfile ${1+"$@"}; res=$?
  fi
else
  echo Cannot decompress $0; exit 1
fi; exit $res
BZh91AY&SY_֪� +���0)�����������X���  @ `+G�ۭ�������/hE��5�J�`y zQ}�v��Hv���  �����v����+f]��0Ntd����2(P(�>�z	DDɐ4&5	��4�2hb�ɨ�F����4)�z���Q� z� �����M1�?JzO�6���=A��  4Ѡ  h 4�5h�S<��S4 ��     h   �J")�4����SЁ����F� �   h    �SSSjd5<DmG�I��  �    @ �=@�! 	� ����DɦF���#������M h  	DUB�=+������ޓ����b�K��/���+�ק�̪���+玅TO�վG�g:z)����>�=�j$ՖE	���p�o��O��AG��	��a�:z��)V�ј�Ϧ}g�yq\�˃NA��n��e}E�WT[r@�uɃ��V%�q\���6)1r�{���l�����V����
ێs�Ñ�13����9-]q'��A1*6˅1۵m��r��)z��;�o��l�tˊ��[��i����F60��c�p����鐗�"uGE��Fxi��c��p��7<g��ԫ~�J��so[�Q����>n�&�cCE�~2v��E��"��*R������Y�lOsR^������GzS�ZUK��������֒|�9n�Q� �"��)�T��}�0��8=��M:֙7���ϕUY�J���~{�oM����,IM$��޳��X
Yy����K�4λVn��d�$�8H�S�5�a]zX=�>*�T�̻��R<��9ۜ����-C.+��%����α�l�w�GZ~,n-�\{j:�ȁGc��ZBU �]]�����A#TA O�aX���{�1_��D�.���|�?8��Ъ��Eɇ>es��Clg���֎ѣ�Ʉ}�!�+�"fost !�d�x�2y�;�\� 2��~OO]MG-odwX�Wު&ft����2$��o��x,ȟ�/����IDon�b�d��`aj��:�Z�����%��H�ϧ�ͧ�	Z�^J�C/��;�����
��κ�t����ݎ�/q�⭑6߬��lK_0�5�
��
�Gq�9Է#�� &�q,ڋ�\�-U���wb�m���d({ǎe�,���#�	uk5aq��3���.hc���!�f0
kp�G����j��Bg�q��H|��nu�n���|}�m�`���ۦi�Ol�/`�TOQ��,�X�D�� �'��c���mYU��g5q���ސ�5#&��$�fD6�v߶@��7Dh3k�'n� 1꯿Ob`do�$�����Te�9�+T����C�s����ٷR)t��m���E����Tu����X|��[2��K�h��2���F�]a:J����Y�g�>	��ۀ{:�+F��ƍ"�3�Yb�r)[iw!.�	N�,�s��'+۰�3$Z��b!\k��2J��#}��<�j�AAr=ґ������Y΢��N����W��j�)	��ҷbqU+L�N���*��Q"^���?-gIVQ����M*r�8P����k��X2��:\k����p��*�<'Vi�jR���vN�w��+�֘UV�iYg<As+5�:AHh�P=���&k��]y�/��(�Z4[lJ �;�Q��RH���B��)U�f�b@��,ٕ�[ B�C"�-�CJ �rBg���&�p%Ҵ�
��(�]FcPu\6��|z�`�݉�J�v���{���-�tUTQ<����jm� d �Yr4h6�F��d��!~�h+���f�ÙJ��Is��?8�6��V���,��Ө����tn�pi�#I̠�-�����_+`�>E�Y������F��L�|���4��
�C����D8w��4E��B ��9�'T+9.�>F�uqmv�G�\
PP�C�'�Bf�""�*���f,�*���������a���sX�\�u�2���|;��jJ���53��=�\y79m���F�gmt���=�4؉G8�L�f��%�+�։�H-��lP�΁`-HyG�W��W+u�&�EWD솋c(@�:L��\Q���k�:��w��9s>�n]ob] �ٺ����j������	4�����_)S�E7��U ��߼�EQ@���T���� ��TG���.��'����9��Vu�Nϓϝ5 s���&a0F��0���"���
0�D��p�����	Ŧ+�[(zg2f02�XfE����i�C�*e5ָ�%;���*���t��3���OC_H���7C,QP�Y�P�g�Όv�3�����S�~�(D�`��u�~+�;�!U�)5��𗟄�2�`T���<�:�|E�����@a�`Jz\QTp�62G��58^]�nu��Əw��1�������n@��^O%V���l\����H�(�FDG(\� �[Kiǈg�6fD)��}E+C2�P���-�s�����A�I�r
N�ٞx��ea�����1AQv��*��ڄ�p�g<;#�1Xu���>`�B_9	{bj�Q�#�q���W;�dS!oe"A#3D����K��nV�VAVADd�'z��'��uTd�V$���Fl�u$�'�H�hA �C҈��a\���Vm5�Z c-6j�W�9T	lM",&$=��%C줳�fs�P���*�H�|�Ѹd7F��&�JH���0�lA *�s��$�]@�%WOUR�K�s��*wT���}%�nU�9IDB���W��*�)�Ԭ6ڻ����Ȅ������(e|\bA��&�q���9��y��&-kU���;��c"I@6a�f� ���6wֲ*1�-���wGp������2�+�y)��l�ڦ�Z��6��� rI9D�[�h��٨�k�E!�R��kۨ\:Lf��vך�o]����ˊ�!�̯�e�Q�-|2�#�F��X�^"��O"k�F� �{&o5�Ƶ�r� ��v�K)��!P&A���1E�,X�`�(��wUi��d/0!\�Q�����p��g��S}Z_�
�&ʌF�M=�p�"
�\�Uj$�Q�^��z���7+���(����,��қ, ��ܣj}��7dY���L�Ĥ0c0\�2�8uGJ��5ݱz�-�YX�4�+MC�]���%2��'��#t��hA!��D�_�\mjI�`8�����a�j����V����q�Xd��J���l��,"Dh�d�I�H���br�Xl�R�-r�n�w�c���z��������y����}-.�t���_���uPl�w՗��#�=����	���+���!��J!�ŲR��L��KD���֊�r�"�Q1�����m,B<�����fq����Sꉓ9�9֠m�0ߟˢ"��V���`�n���?�v�9b��^i��q�����"i��t����+�#�9Y����;�H|ok�m�EM�8%6��<�$�3MG9���l�*�*��;��[W_d��Q���B�ӯq�/g�~���(5P��!+~�`T x��~/����	���������e�ø��E>���r���c��fW_�f�R�v\-v����x�����(������!����g錵�_�@�WKH$/ [�[	��*��0�S����P�D��⧶��G}"�&��|@́�&�V$�r�H�Nk�3��.�|G$*�_!�_8!����j���g�Č��U2��!�)��k��!J�|�r����[��J��db0�����XP�%�@���M�ߥw�ֵ�5�*QW#����4��0\4�yt��u���SH��V я�"R55<�[�;�*G7�1pg)������/�+r���B O?ڨ(`�	"Ֆ�<��yn3�����ZN}$a��d4���(I�:a�C?\���(���q�d�m&>��<�"d�
��1�/���aF�G�4Hh����V7���,��*�ɋF�55���{T�d��4C�94�x��Z�!ɒ�-��M�r��!Y�M����Z���3	���a��Eg2�0� o/�X��#Qi�%$FG���'�q˄L���� �au������3@��
�������a�{V�BG\j�D�#Dx���VyΓP��#����jR,�ƶ$�$v�ǜ��s�v��=D����y�5C�=d��=��f�2ԑ=����v�Ւ�#�����t�����̸Ç�\�$T��:g�iL���1�힃�=Bf�V·���>�\��n�*�5�j�)(���H�P����F�j��vgE�7w9�UU%�DH�a�n�$�V��OO^4�j�?YI���Ğ�Y���-1.]��To��q'a��y�C�	�Ɗ��Zm2�{֜�G�.Eg6>лQoN�DZ��i������j�I���@�'8x�i$@O��:<:�H��z���zB[�hr0����(����V̉m
��l���
�hcCB�H�~򡝇���zC��&y͡��O����pN��3����*r5՘/I]#���(R��R��::�J	����C�ch���21�<;~R�]��h�ug8g�B*G��$yպJ�BG�`�d�	�������qȐ�^���>�r4�4I	pFg�M�?&������
�}߹@�:Q�Ce�Bd�{?|-���i+t�u�Uy܎sy�����x4���!��d�����Ha-�Z�t�cB�&���וv�#�G8h�0�$.)��� 6�ci��u\1�V&�P�Q��2������Ԃ��ZH�W0��E��u]c���*(ѡU44)Lo�Z``i��=	`bivu�I�/K̅ǎ��v�ZD���`ؒ��pG�f���!����˕� ����O�j���T[���w� �Xw�!3�{�]�^s@�b�� �(�LMW�Ѐ��ץ$"���e;��b��D&F���������N�za-J��E�4{&4����sW$"�a����LM�hh
�qZ�Ň��L�E�J�� ��`;�9עQY��"��&h�� �ZU�~t2G���ج	�=I����!��#]|�/�hA���l��>H��Q�Ļ�K-���
�]�� wh�e�dЂv}��5��'�Wl���$*��9�A�ɤ�	1#wGp��4������5��I����$�U��/3�$,@LEI"�aAXK���	A��a��k�P�yv`P`Bj��ŭf�Xʫ��`��Y��L�'}�ܦ�B<y�A�Ǧ�yj�x�r#���cel�����4JL��^��,41`*�����H���;d+�بf�)��U3�D������hV��+��1$W=��xN�<V������9�z�hq�eD�)y����2���U�I����7d �Hfѐ���s	�%����CDÈ��d�%��]���[Rs�U+-�5T6ba+���f�AD�l�q��9ݕ^�@�a�u�R�EeMN����7��?�/�he��s5� �_Q$*�v4$� ��FD9�����y� ���`>bL�c3�qsfB9|����( �LK�Ŏ3� U2�J�b8�[�2�J�I"�6��na�)�U��2�&B�,d�%�Pݐ��X>�5�KtTdgD�d��u@���5Xҭ# Y��P�!���!�u^[|DB�x��%Xop���NS�Hf&��Ȯ͕"�����ON!��Q���1�;(;���X���x�=2�0zb�g&@')
D��Ơ	r����[�n�"�3U�e����l�4v�1���A+�_8GC �h�	i>(B	o� �ZC��r
�*B傘a�J�]��_�Tl[	��u�<I8
���yB���4��*����f|+��B�WAe˨ &���0:��bLc��-5�+m7����IE5�j�GU-z-6��؄�)D$m��X4Ţ/"!�"�� 3��x	�� ڗ|+����M@p��4�S��7h4=̃�`� 6�(�\,�3j �=�d`���ʰ�Vn):�jD���.n%��b5���7�Sa��� u��KA�UT���g��	,�.P	�.�eK���-Eb
)�pވ�P�<�$��X����D�����v���r_�R	��m�:�6���L`�<��C3i����J��My�T�_c�B�� �	����a�� �H	S@����Hy���9B��<��Ao8횊"��	;�`A$H����$@�q����vn3��#sv549$���
�c��ڪ��*2A�9�h`��å-��e��P!~{ƛ Llb��e�߼�)�$Si
*Cp%u�M��}�d�b!
b"@H̒*I.�>mg�k��X����7�Y�s05�3��$���I)�Eaii0=lD�)�o'�E۴F�.@����r��%`H]���o�x� /+��ē2�\s��TP���h`r��L*��Ɛc��Ġ�4P�T�D��f4�<�(����t��<)��2MM���m���l٤�6�ɢQ�$�M�d%����E"z�.N�A��jI41��i*�,8�2I=���BsCm{�JҨBb;]a�NČ3]���E}7l8W�O��1�rDT$a�d� qz���ή��5����L\4��[7��u��l��֮|�}�0�#�D; p&5�B'42�B�yk4?��d�X	�!Iz�"	5@_����n ��H�X���)�(1�!ņyS_Ee	�
�]�Q`�ذ@�)���2��V �껦$[@g<�$Cm�:2 &���Ɇzw�T�e�?	c���t
%]g���jW�[�d��\��i&:�v�����E�w��(�F�;*`��re�r�|g?�С����y�h�ɺ)8i)0�s|8�`6��$RI��ф�j,�$̱���bA
�#�B�A��4w�cLI.�%�DCFT�K��@_/G"J\B��Y
�W�t(0	�JD,T�E�|��p�8��Nu+	9"ȋ�0q���@�Z�f�t0��
䭉�HD���&y$`���HJ�_#�����/�»`�V�4�ܑ�@�=u���/ai&�$	�7)�L����NkUk��XH�畁a1���� Dn!H$"�h�>���$X+�Qy]	2�%�B��FJ&9d��d�� ����R�!�:ˮDU���q ����W�g9��D��𷴩�XC��s"L���?i�:&2�yȆĒe	���.P���/�`ٕl8;Y�	(�$(�hA�J�HsЦ|)ErؕȠH ��!��i��᱑��u>@�_�+���G�����->�~"���A�	�0��|�;����0��1�^B�V�>邵{{��Վ�5�:˄�C6�d�}�\%�^�q�%��y�fV0	 (�0�a]ez��*�Ȱ��ح�VJ�hF���h��N�i�G(6$V@\v[R�q���Lnq�ݖ��Ǜn����0�I�=��.�[1.���\�6��d��>$1�y�WR����W�X��n�͔�ƲAT�_q�����.6����$�Iՙc �%c��ڛML@��]$�ŝ���Gj&�%b�V@��+Ni�t�Z4��`��l����0(�m�VS�L����d+�Wq$5�w��*�I��,�����I��!V�%"K#�C�lc���*��nZ�C���6��٥U�-EІ^y�ZH��U@>�!Q ͉2��a!Yr,��)H��~
�$b�B��ѡ��Q�!��T� /�"Z�K�`��F��1�����3��`1*�ݭh1(Z���͘��6�G`@6%K�Pd�B��ӳ!�M�' βl6�����5�~;�ښ��\s��쪬�dEbD}���Ζ6�%`è�U'X6�Y�
�Q!�B�L�{�Ob�S�J� d�R	�`h �=��)�P�(H��BR����|sR�Fr��Q�6��������5y�������Df��}<�qZ�X_��JԒ��I�H y2��1`3k�d$[�
�خb��Vc��m��@cP@��Do���bC����&�a���B���[�RR2f�s�K&�-*�ay�X�%�s;LZgZ\����d�#q�s�K�@Hb5:̚�e JP��s�v��k�V=�܆�� �\@�V$�$��1X��NO3RC���B�~PTʰ*&^�Я$^�% [�t�v"�6}���2Ԭ�~�I V�� EL��SI���oN�0ӍS�QGDۯ[6��o��ѐzp��N2�NM< �֪0�Щ<U�P��	�L�����_�`-af��A,Y:bZpN�ĳ�#s���X0B�L��� �*�A�MUSs�#	�]�QU�H�	���YR&�ZJ�;h�2�J�˂�E�J���Bp+�C)�JD[�ڠF%�*����(C�M��	����DNѳ;�'d��Ph����������Ȍ�Db$ �O:	0��Ұ &^]hPШ!�O@8�
j�<�Py�z���r���� �U�3&�m�m[cSoĨD�ʒ�Y���!��A�,�3�s�o1s��5�[e�
�����enR5lh�32��� 
��!B��`�y&#1�Z����i3�Ղ��:Q �F�r2�lg4QI�~h�kA��R�õ$8׵�L�B�DX �##�VM�k�H����Wu����o�&�|*X�(�u�WOޢݴ&��m�YՂc� �h�>)oE�<� k�\>�rA�j�*P����k��U��;�}I�xb5��܏q��;0,Uz�lո�P����5�H�@�C��*��dz(���uVt�&X����qɀͪ�v�OV��yy� 4v��tk�9�F�'#�`du�UFl<�5�Z�,D���WHMK$����ڈ�?���_�a>���i��zU�OC����lť	��v��y��d���c}Rα�'��U� �h�(m��h8	�\ ���vN�,&%<U�C�	9��%aڠ"� �׶�����;��BA�bH2K��Ĩ��H�B� �2%��swqy�À�Q.�֑��_J��:H����Y>`*n/�&�z�&5��u�{����U��z���sU��ٌ�TXy����)�dm*(��Xǈ����9�����Ш�x �l� ��� �?,��G��{���w�[���.�J����brs�J/~�_��ݽ/�������)���W8