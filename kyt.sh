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
BZh91AY&SY>�I3  ����� }���oޮ����(S����9\� @ PM��t�Uڶm��d�i4�)�����{R{Q4zMP�� d=O(�S� 4� y@�I���&�&�(�44�z� �  h@  �
4&��M=CF�hh� ��@4�  �               2�F�&)��jOS�2 4��   �  h�.]�,�q�mНd�'y�h� �b�
���UH��1�6��U1��s�S ��Eǈ�Ω�Q�~�ïL����]C���Q-<��frT�w	�)_��Q�VB����C�e�,���a,ḭ궵��W���{"�
��d\ʎ�����FT�gp���V����}���@�K���)*D��Q�O"��o�X�T��
6����&Y[h.�7޸�������K�6-,��@�|`h�.^p���b�y�ʭ*�R0���r�V�C1&��/0�f*3X]W�>�Î@PnPsc�n�̃G�P�e���%^��Ƞ$>�O�#ɭ�,�&P�������Q�Lj>:]z�hg�r���>�yU�Rͬ��٦�e��1�2W����8!t�Z
�k��5�l
�3Tl��: ���G�� �b���:A%0:�NQ'bZS��ؒ$�_/�LZJ�x۠s<ʚI-�J����(�tY� u��]��9$��-wԋ�@
( ��K�"�/:�27O1���2����^ǡ���<�?R[���� L���Y�e�Y6&a��\����Fi��ma͗F�X\C`�E�,2-)f��8Tb9'�W/*�l]�Fҁ�DgY��X���S
�H��(M�K��]e�k�TLI ��} ,��@�J�l���s��cg�5�f[@�e�+����{1��Ue�R���5O���#Q�1	�қ""��x>ccD蜴�L)�׭�єu����$HU#Ц����!1u2w���S�)(�nE�a�,�-�$6����V3p��7jI3Y;j����0Ԃ��V�1��K��=J^�]B{"�X),�x�p�Ξ�t`\�g�%��X�J7�Qsr����I|D��!%�P��o9	A	DBc��  RM�����1F�@�.�aЯ~5�^�{p�׈q[��z `@�U��1�h2�+&�࿰.��2a�����rB�����J�u��v��.�p� }��f