
name := "iohk-hoop"

version := "0.1"

scalaVersion := "2.11.8"

unmanagedJars in Compile ++= {
  val baseDirectory = Path("/usr/lib/scapi/")
  val customJars = (baseDirectory / "commons-exec-1.2.jar") +++ (baseDirectory / "bcprov-jdk16-146.jar") +++ (baseDirectory / "Scapi-2.4.jar")
  customJars.classpath
}

libraryDependencies += "joda-time" % "joda-time" % "2.8.2"

libraryDependencies += "ch.qos.logback" % "logback-classic" % "1.1.2"

libraryDependencies += "org.scalatest" %% "scalatest" % "2.2.6" % Test

libraryDependencies += "com.typesafe.akka" %% "akka-testkit"  % "2.4.+" % Test

libraryDependencies += "org.scalactic" %% "scalactic" % "2.2.6"

libraryDependencies += "com.typesafe.akka" %% "akka-actor" % "2.4.+"

libraryDependencies += "com.typesafe.akka" % "akka-slf4j_2.11" % "2.4.8"

libraryDependencies += "com.typesafe" % "config" % "1.2.1"

libraryDependencies += "org.scalacheck" %% "scalacheck" % "1.12.5" % Test

