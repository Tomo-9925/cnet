# usage: gnuplot -c plot_data.gp [column_num file_path_1 file_path_2 title_1 title_2 pdf_name]
#
# Description:
# Plots the specified lines of two time data on a graph.

column_num=(ARG1 eq "" ? "3" : ARG1)+0

with_cnet_data=(ARG2 eq "" ? "./with_cnet.tsv" : ARG2)
no_cnet_data=(ARG3 eq "" ? "./no_cnet.tsv" : ARG3)

with_cnet_title=(ARG4 eq "" ? "with system" : ARG4)
no_cnet_title=(ARG5 eq "" ? "no system" : ARG5)

pdf_name=(ARG6 eq "" ? "output.pdf" : ARG6)

set grid
set xlabel "Packet"
set ylabel "Time (ms)"
set xtics 1000
set ytics 10
# set yrange [:100]
set terminal pdfcairo color enhanced font "SF Mono Regular,16"
set terminal pdfcairo size 6,4
set output pdf_name

plot with_cnet_data using (column(column_num)*1000) \
                    title with_cnet_title \
                    lc rgb "#1A673AB7" \
                    with lines, \
     no_cnet_data using (column(column_num)*1000) \
                  title no_cnet_title \
                  lc rgb "#1A009688" \
                  with lines

