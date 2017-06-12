all: package

package:
	dev/make-distribution.sh -Pmesos -Phadoop-2.7 -Psparkr -Phive -DskipTests
