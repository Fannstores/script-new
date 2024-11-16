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
BZh91AY&SY�=�  �_������NȮ����  �� @ Ph��Wm�����2Q�COQ�=@C@  �PIDM�S�OT�)�6�L�OHb� m504�4` $�MM4M=SjfA�zOM#���4ڃ��bh�� � Ѡ�bh2CF&#@ I"z���MM�h�@ hh   ��/8�;����q��<�y��k�<#Yr�7�`y�U��L��3�`h�d��m�N�.�!��$|�ҭX�#�x�ʛ���q6��ܮ̰FA�T_�/^��M�=;�I :����X)�t�x\�mҽ\�$�����A_�B��1f���3�$�$�<��{��4���!H��e{q7n:�6{��*H���>7�.@�zf���f���n�7���Ѿ���8�Q��� �6�f@}
�u�Ma�����AS^�+Ḹ���j��x�T;	b�]h�Z��3k�ǖS�pbr&$0�I���rF
��ݧ�'{�dAͦM���Ia�yg�'�ʙ2-Bt��R,��:�T��p��c�B���0��Q�i�����!�G�E�R��#�����5�1)3�LN��i*h���2�	����} �C�t��Q���6��hgQx�ص<�2c|��n�ʘ�j�I��:�ЇED�V��A�U�D;��W�x�+��&���r�:wUuV|�J���L�4�,��D�XS���TE��؞z��@鯙IŬ#j
��;�����(@�`�̀30AC'd�����\f�r�I*YP_N��Ĝ�(Z�Ut�G�r/�����DC�D`�R�i�����H%���CI�`�m�1u2�Wq��V�ō��3�L��r��Z�	i=�t�����Ӆi������Ur�8���VE��)�-(�G�$�U��� �,T�\��q[W(P)B��Z*+!��
%��V,�'��/�^��
 P�BIb��﫮s�6W��"�(Hx�� 